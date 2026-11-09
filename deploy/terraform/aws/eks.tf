# Optional EKS cluster (create_eks = true). Small, single node group.

data "aws_availability_zones" "available" {
  state = "available"
}

module "vpc" {
  count   = var.create_eks ? 1 : 0
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.13"

  name               = "${var.name}-vpc"
  cidr               = "10.42.0.0/16"
  azs                = slice(data.aws_availability_zones.available.names, 0, 2)
  private_subnets    = ["10.42.1.0/24", "10.42.2.0/24"]
  public_subnets     = ["10.42.101.0/24", "10.42.102.0/24"]
  enable_nat_gateway = true
  single_nat_gateway = true

  public_subnet_tags  = { "kubernetes.io/role/elb" = 1 }
  private_subnet_tags = { "kubernetes.io/role/internal-elb" = 1 }
}

module "eks" {
  count   = var.create_eks ? 1 : 0
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.24"

  cluster_name                             = var.name
  cluster_version                          = "1.31"
  cluster_endpoint_public_access           = true
  enable_cluster_creator_admin_permissions = true
  vpc_id                                   = module.vpc[0].vpc_id
  subnet_ids                               = module.vpc[0].private_subnets

  cluster_addons = {
    aws-ebs-csi-driver = {}
    coredns            = {}
    kube-proxy         = {}
    vpc-cni            = {}
  }

  eks_managed_node_groups = {
    default = {
      instance_types = ["t3.medium"]
      min_size       = 1
      max_size       = 2
      desired_size   = 1
      iam_role_additional_policies = {
        ebs = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
      }
    }
  }
}

output "eks_kubeconfig_command" {
  value = var.create_eks ? "aws eks update-kubeconfig --region ${var.region} --name ${var.name}" : "EKS not created (create_eks = false)"
}
