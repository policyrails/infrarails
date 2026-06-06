resource "aws_s3_bucket" "logs" {
  bucket = "${var.name_prefix}-${var.account_id}-bedrock-logs"
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    id     = "expire-bedrock-logs"
    status = "Enabled"
    expiration {
      days = var.expiration_days
    }
  }
}

resource "aws_bedrock_model_invocation_logging_configuration" "this" {
  logging_config {
    text_data_delivery_enabled = true
    s3_config {
      bucket_name = aws_s3_bucket.logs.id
    }
  }
}
