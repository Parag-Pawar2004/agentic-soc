# Local Kubernetes on your laptop (needs only Docker): creates a kind cluster,
# installs the NGINX ingress controller, then installs the Agentic SOC Helm chart.
#
#   cd deploy/terraform/local
#   terraform init
#   terraform apply -var="dockerhub_user=YOURNAME" -var="analyst_password=..."
#
# Then add "127.0.0.1 soc.local" to your hosts file and open http://soc.local

terraform {
  required_version = ">= 1.5"
  required_providers {
    kind = { source = "tehcyx/kind", version = "~> 0.6" }
    helm = { source = "hashicorp/helm", version = "~> 2.17" }
  }
}

variable "cluster_name" {
  type    = string
  default = "agentic-soc"
}
variable "dockerhub_user" {
  type        = string
  description = "Docker Hub account the GitHub Actions workflow pushes images to"
}
variable "image_tag" {
  type    = string
  default = "latest"
}
variable "analyst_password" {
  type      = string
  sensitive = true
}
variable "openrouter_api_key" {
  type      = string
  sensitive = true
  default   = ""
}
variable "groq_api_key" {
  type      = string
  sensitive = true
  default   = ""
}

resource "kind_cluster" "soc" {
  name           = var.cluster_name
  wait_for_ready = true

  kind_config {
    kind        = "Cluster"
    api_version = "kind.x-k8s.io/v1alpha4"

    node {
      role = "control-plane"
      kubeadm_config_patches = [
        "kind: InitConfiguration\nnodeRegistration:\n  kubeletExtraArgs:\n    node-labels: \"ingress-ready=true\"\n"
      ]
      extra_port_mappings {
        container_port = 80
        host_port      = 80
      }
      extra_port_mappings {
        container_port = 443
        host_port      = 443
      }
    }
  }
}

provider "helm" {
  kubernetes {
    host                   = kind_cluster.soc.endpoint
    cluster_ca_certificate = kind_cluster.soc.cluster_ca_certificate
    client_certificate     = kind_cluster.soc.client_certificate
    client_key             = kind_cluster.soc.client_key
  }
}

resource "helm_release" "ingress_nginx" {
  name             = "ingress-nginx"
  repository       = "https://kubernetes.github.io/ingress-nginx"
  chart            = "ingress-nginx"
  namespace        = "ingress-nginx"
  create_namespace = true
  wait             = true

  values = [yamlencode({
    controller = {
      hostPort     = { enabled = true }
      service      = { type = "NodePort" }
      nodeSelector = { "ingress-ready" = "true" }
      tolerations  = [{ key = "node-role.kubernetes.io/control-plane", operator = "Equal", effect = "NoSchedule" }]
      publishService = { enabled = false }
      extraArgs    = { "publish-status-address" = "localhost" }
    }
  })]
}

resource "helm_release" "soc" {
  name             = "agentic-soc"
  chart            = "${path.module}/../../helm/agentic-soc"
  namespace        = "soc"
  create_namespace = true
  depends_on       = [helm_release.ingress_nginx]

  set {
    name  = "image.owner"
    value = var.dockerhub_user
  }
  set {
    name  = "image.tag"
    value = var.image_tag
  }
  set_sensitive {
    name  = "secrets.ANALYST_PASSWORD"
    value = var.analyst_password
  }
  set_sensitive {
    name  = "secrets.OPENROUTER_API_KEY"
    value = var.openrouter_api_key
  }
  set_sensitive {
    name  = "secrets.GROQ_API_KEY"
    value = var.groq_api_key
  }
}

output "url" {
  value = "http://soc.local  (add '127.0.0.1 soc.local' to your hosts file)"
}
output "kubeconfig_hint" {
  value = "kubectl config use-context kind-${var.cluster_name}"
}
