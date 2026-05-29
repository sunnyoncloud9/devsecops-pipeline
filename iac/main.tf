# Sample Terraform — AWS infrastructure for the sample app
# This is scanned by Checkov in the IaC stage of the pipeline.
# Demonstrates secure-by-default infrastructure configuration.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# S3 bucket with security best practices
resource "aws_s3_bucket" "app_data" {
  bucket = "scaniq-sample-app-data"
}

# Block all public access — Checkov check CKV_AWS_53/54/55/56
resource "aws_s3_bucket_public_access_block" "app_data" {
  bucket = aws_s3_bucket.app_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable encryption at rest — Checkov check CKV_AWS_19
resource "aws_s3_bucket_server_side_encryption_configuration" "app_data" {
  bucket = aws_s3_bucket.app_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

# Enable versioning — Checkov check CKV_AWS_21
resource "aws_s3_bucket_versioning" "app_data" {
  bucket = aws_s3_bucket.app_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Enable access logging — Checkov check CKV_AWS_18
resource "aws_s3_bucket_logging" "app_data" {
  bucket        = aws_s3_bucket.app_data.id
  target_bucket = aws_s3_bucket.app_data.id
  target_prefix = "access-logs/"
}

# Security group with least privilege
resource "aws_security_group" "app" {
  name        = "scaniq-app-sg"
  description = "Security group for sample app"

  # Only allow HTTPS inbound
  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Restrict egress
  egress {
    description = "HTTPS outbound only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
