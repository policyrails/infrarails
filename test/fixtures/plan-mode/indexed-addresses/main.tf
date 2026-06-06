resource "aws_cloudtrail" "main" {
  name                          = "ai-audit-trail"
  s3_bucket_name                = "some-trail-bucket"
  enable_logging                = true
  is_multi_region_trail         = true
  include_global_service_events = true
}

module "bedrock_governance" {
  source  = "terraform-aws-modules/bedrock-logging/aws"
  version = "1.0.0"
  count   = 1
}

resource "aws_bedrockagent_agent" "writer" {
  agent_name = "writer-agent"
  guardrail_configuration {
    guardrail_identifier = "g-1"
    guardrail_version    = "1"
  }
}

resource "aws_bedrock_guardrail" "safety" {
  name                      = "safety"
  blocked_input_messaging   = "blocked"
  blocked_outputs_messaging = "blocked"

  content_policy_config {
    filters_config {
      type            = "PROMPT_ATTACK"
      input_strength  = "HIGH"
      output_strength = "NONE"
    }
    filters_config {
      type            = "HATE"
      input_strength  = "HIGH"
      output_strength = "HIGH"
    }
  }
}
