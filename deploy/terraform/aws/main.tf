# AWS resources for the SOAR integration.
#
# By default this creates only cheap, pay-per-use-free pieces:
#   * a WAFv2 IP set the response agent adds blocked IPs to (attach it to your
#     existing Web ACL / ALB / CloudFront to enforce it)
#   * an IAM policy + user scoped to exactly that IP set (and optionally IAM key disabling)
#
# Set create_eks = true to also build a small EKS cluster for the Helm chart.
# EKS and its nodes cost money every hour - read the AWS pricing page first.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.70" }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "ap-south-1"
}
variable "name" {
  type    = string
  default = "agentic-soc"
}
variable "waf_scope" {
  type        = string
  default     = "REGIONAL"
  description = "REGIONAL for ALB/API Gateway, CLOUDFRONT for CloudFront (must use us-east-1)"
}
variable "allow_iam_key_disable" {
  type    = bool
  default = false
}
variable "create_eks" {
  type    = bool
  default = false
}

resource "aws_wafv2_ip_set" "blocklist" {
  name               = "${var.name}-blocklist"
  scope              = var.waf_scope
  ip_address_version = "IPV4"
  addresses          = []
  description        = "Managed by Agentic SOC after analyst approval"

  lifecycle {
    ignore_changes = [addresses] # the SOC edits this list at runtime
  }
}

data "aws_iam_policy_document" "soar" {
  statement {
    sid       = "EditBlocklistOnly"
    actions   = ["wafv2:GetIPSet", "wafv2:UpdateIPSet"]
    resources = [aws_wafv2_ip_set.blocklist.arn]
  }
  dynamic "statement" {
    for_each = var.allow_iam_key_disable ? [1] : []
    content {
      sid       = "DisableCompromisedKeys"
      actions   = ["iam:ListAccessKeys", "iam:UpdateAccessKey"]
      resources = ["arn:aws:iam::*:user/*"]
    }
  }
}

resource "aws_iam_policy" "soar" {
  name   = "${var.name}-soar"
  policy = data.aws_iam_policy_document.soar.json
}

resource "aws_iam_user" "soar" {
  name = "${var.name}-soar"
}

resource "aws_iam_user_policy_attachment" "soar" {
  user       = aws_iam_user.soar.name
  policy_arn = aws_iam_policy.soar.arn
}

output "env_for_dot_env" {
  description = "Paste into .env (create an access key for the user in the AWS console)"
  value       = <<-EOT
    FIREWALL_PROVIDER=aws_waf
    AWS_REGION=${var.region}
    AWS_WAF_SCOPE=${var.waf_scope}
    AWS_WAF_IPSET_NAME=${aws_wafv2_ip_set.blocklist.name}
    AWS_WAF_IPSET_ID=${aws_wafv2_ip_set.blocklist.id}
  EOT
}
