# Terraform

| Folder | What it creates | Cost |
|---|---|---|
| `local/` | A kind Kubernetes cluster in Docker on your laptop, NGINX ingress, and the Agentic SOC Helm release | Free |
| `aws/` | A WAF IP set the SOC can add blocked IPs to, plus a least-privilege IAM user/policy. `create_eks = true` adds an EKS cluster | IP set + IAM: free. EKS: billed hourly |

Install Terraform from https://developer.hashicorp.com/terraform/install, then:

```bash
cd deploy/terraform/local
terraform init
terraform apply -var="dockerhub_user=YOUR_DOCKERHUB_NAME" -var="analyst_password=CHOOSE_ONE"
```

The local stack pulls images from Docker Hub, so run the GitHub Actions
"Docker images" workflow once first (it happens automatically on every push to `main`).
