# Terraform owns the Bedrock invocation-logging configuration; the storage it
# points at (bucket + log group) is declared in the CloudFormation template
# sitting next to this file. Mixed-dialect estates are common: a platform team
# ships CFN StackSets while the app team writes Terraform.
resource "aws_bedrock_model_invocation_logging_configuration" "this" {
  logging_config {
    s3_config {
      bucket_name = "mixed-ai-logs"
    }
    cloudwatch_config {
      log_group_name = "/aws/bedrock/mixed"
    }
  }
}
