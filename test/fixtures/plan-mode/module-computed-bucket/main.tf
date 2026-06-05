resource "aws_cloudtrail" "main" {
  name                          = "ai-audit-trail"
  s3_bucket_name                = "some-trail-bucket"
  enable_logging                = true
  is_multi_region_trail         = true
  include_global_service_events = true
}

# Local module (HCL is on disk under ./modules/logging). The Bedrock logging
# config and its log bucket live inside it, and the bucket name is built from the
# account id, so Terraform reports it computed-at-apply (after_unknown) in the
# plan. The scanner must still anchor on the HCL reference to identify the bucket.
module "logging" {
  source          = "./modules/logging"
  name_prefix     = "recruiter"
  account_id      = "123456789012"
  expiration_days = 90
}
