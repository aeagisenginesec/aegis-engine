variable "region" {
  type        = string
  description = "AWS region"
}

variable "project" {
  type        = string
  description = "Project name prefix"
}

variable "table_name" {
  type        = string
  description = "DynamoDB table name"
}

variable "function_name" {
  type        = string
  description = "Lambda function name"
}
