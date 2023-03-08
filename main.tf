module "db" {
  count                               = var.create ? 1 : 0
  source                              = "terraform-aws-modules/rds/aws"
  version                             = "5.6.0"
  allocated_storage                   = var.allocated_storage
  allow_major_version_upgrade         = var.allow_major_version_upgrade
  apply_immediately                   = var.apply_immediately
  auto_minor_version_upgrade          = var.auto_minor_version_upgrade
  backup_retention_period             = var.backup_retention_period
  backup_window                       = var.backup_window
  character_set_name                  = var.character_set_name
  copy_tags_to_snapshot               = var.copy_tags_to_snapshot
  create_db_option_group              = false
  create_db_parameter_group           = false
  create_db_subnet_group              = true
  create_monitoring_role              = true
  db_subnet_group_description         = "Subnet group for ${var.instance_name}. Managed by Terraform."
  db_subnet_group_name                = var.instance_name
  db_subnet_group_use_name_prefix     = var.db_subnet_group_use_name_prefix
  deletion_protection                 = var.deletion_protection
  domain                              = var.domain_id
  domain_iam_role_name                = aws_iam_role.ad[count.index].name
  enabled_cloudwatch_logs_exports     = ["agent", "error"]
  engine                              = var.engine
  engine_version                      = var.engine_version
  family                              = var.parameter_group_family
  iam_database_authentication_enabled = var.iam_database_authentication_enabled
  identifier                          = var.instance_name
  instance_class                      = var.instance_class
  iops                                = var.iops
  kms_key_id                          = var.kms_key_id
  license_model                       = var.license_model
  maintenance_window                  = var.maintenance_window
  major_engine_version                = var.major_engine_version
  max_allocated_storage               = var.max_allocated_storage
  monitoring_interval                 = var.monitoring_interval
  monitoring_role_name                = var.monitoring_role_name == null ? "${var.instance_name}-monitoring-role" : var.monitoring_role_name
  multi_az                            = var.multi_az
  option_group_name                   = aws_db_option_group.mssql_rds[0].name
  parameter_group_name                = aws_db_parameter_group.db_parameter_group[count.index].name
  password                            = random_password.root_password[count.index].result
  performance_insights_enabled        = var.performance_insights_enabled
  performance_insights_kms_key_id     = var.performance_insights_kms_key_id
  port                                = var.port
  publicly_accessible                 = var.publicly_accessible
  skip_final_snapshot                 = var.skip_final_snapshot
  snapshot_identifier                 = var.snapshot_identifier
  storage_encrypted                   = true
  storage_type                        = var.storage_type
  subnet_ids                          = var.subnets
  tags                                = var.tags
  timezone                            = var.timezone
  username                            = var.username
  vpc_security_group_ids              = [aws_security_group.db_security_group[count.index].id]
}

resource "aws_db_parameter_group" "db_parameter_group" {
  count       = var.create ? 1 : 0
  name_prefix = var.instance_name
  description = "Terraform managed parameter group for ${var.instance_name}"
  family      = var.parameter_group_family
  tags        = var.tags
  dynamic "parameter" {
    for_each = var.db_parameters
    content {
      name         = parameter.value.name
      value        = parameter.value.value
      apply_method = parameter.value.apply_method
    }
  }
}

#-----------------------------------------------------------------------------
# these 4 objects below define the root secret.

resource "aws_secretsmanager_secret" "db" {
  count       = var.create && var.store_master_password_as_secret ? 1 : 0
  name_prefix = "database/${var.instance_name}/master-"
  description = "Master password for ${var.username} in ${var.instance_name}"
  tags        = var.tags
}

resource "aws_secretsmanager_secret_version" "db" {

  count     = var.create && var.store_master_password_as_secret ? 1 : 0
  secret_id = aws_secretsmanager_secret.db[count.index].id
  secret_string = jsonencode({
    "username"       = "root"
    "password"       = random_password.root_password[count.index].result
    "host"           = module.db[count.index].db_instance_address
    "port"           = module.db[count.index].db_instance_port
    "dbname"         = "master"
    "connect_string" = "${module.db[count.index].db_instance_address},${module.db[count.index].db_instance_port}"
    "engine"         = "mssql"
  })
}

resource "random_password" "root_password" {
  count = var.create ? 1 : 0

  length  = var.random_password_length
  special = false
  numeric = false
}

data "aws_secretsmanager_secret_version" "db" {
  count = var.create ? 1 : 0

  # There will only ever be one password here. Hard coding the index.
  secret_id  = aws_secretsmanager_secret.db[count.index].id
  depends_on = [aws_secretsmanager_secret_version.db]
}

#-----------------------------------------------------------------------------

resource "aws_security_group" "db_security_group" {
  count  = var.create ? 1 : 0
  name   = var.instance_name
  vpc_id = var.vpc_id
  tags   = var.tags

  ingress {
    from_port   = var.port
    to_port     = var.port
    protocol    = "tcp"
    cidr_blocks = var.ingress_cidrs
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = var.egress_cidrs
  }
}

# Define the option group explicitly.
resource "aws_db_option_group" "mssql_rds" {
  count = var.create ? 1 : 0

  name_prefix              = var.instance_name
  option_group_description = "MSSQL RDS Option Group managed by Terraform."
  engine_name              = var.engine
  major_engine_version     = var.major_engine_version
  tags                     = var.tags

  dynamic "option" {
    for_each = var.mssql_options
    content {
      option_name                    = option.value.option_name
      port                           = lookup(option.value, "port", null)
      version                        = lookup(option.value, "version", null)
      db_security_group_memberships  = lookup(option.value, "db_security_group_memberships", null)
      vpc_security_group_memberships = lookup(option.value, "vpc_security_group_memberships", null)

      dynamic "option_settings" {
        for_each = lookup(option.value, "option_settings", [])
        content {
          name  = lookup(option_settings.value, "name", null)
          value = lookup(option_settings.value, "value", null)
        }
      }
    }
  }
}

################################################################################
# Create an IAM role to allow access to the s3 data archive bucket
################################################################################

resource "aws_db_instance_role_association" "s3_data_archive" {
  count                  = var.create && var.archive_bucket_name != null ? 1 : 0
  db_instance_identifier = module.db[count.index].db_instance_id
  feature_name           = "S3_INTEGRATION"
  role_arn               = join("", aws_iam_role.s3_data_archive.*.arn)
  depends_on = [

  ]
}

resource "aws_iam_role" "s3_data_archive" {
  count              = var.create && var.archive_bucket_name != null ? 1 : 0
  name               = "s3-data-archive-${lower(var.instance_name)}"
  assume_role_policy = join("", data.aws_iam_policy_document.assume_s3_data_archive_role_policy.*.json)
  tags               = var.tags

}

resource "aws_iam_role_policy_attachment" "s3_data_archive" {
  count = var.create && var.archive_bucket_name != null ? 1 : 0
  role  = join("", aws_iam_role.s3_data_archive.*.name)
  # The actions the role can execute
  policy_arn = join("", aws_iam_policy.s3_data_archive.*.arn)
}

resource "aws_iam_policy" "s3_data_archive" {
  count       = var.create && var.archive_bucket_name != null ? 1 : 0
  name        = "s3-data-archive-${lower(var.instance_name)}"
  description = "Terraform managed RDS Instance policy."
  policy      = join("", data.aws_iam_policy_document.exec_s3_data_archive.*.json)
}

data "aws_iam_policy_document" "assume_s3_data_archive_role_policy" {
  count = var.create && var.archive_bucket_name != null ? 1 : 0
  statement {
    actions = [
      "sts:AssumeRole"
    ]

    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["rds.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "exec_s3_data_archive" {
  count = var.create && var.archive_bucket_name != null ? 1 : 0
  statement {
    actions = [
      "s3:ListBucket",
      "s3:GetBucketLocation",
      "s3:GetBucketACL"
    ]
    resources = [
      "arn:aws:s3:::${var.archive_bucket_name}"
    ]
    effect = "Allow"
  }

  statement {
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListMultipartUploadParts",
      "s3:AbortMultipartUpload"
    ]
    resources = [
      "arn:aws:s3:::${var.archive_bucket_name}/*"
    ]
    effect = "Allow"
  }

  statement {
    actions = [
      "s3:ListAllMyBuckets"
    ]
    resources = [
      "*"
    ]
    effect = "Allow"
  }

  dynamic "statement" {
    for_each = { for a in [var.kms_key_id] : a => a }
    content {
      actions = [
        "kms:Decrypt",
        "kms:Encrypt",
        "kms:DescribeKey"
      ]
      resources = [
        statement.value
      ]
      effect = "Allow"
    }
  }
}

################################################################################
# Create an IAM policy to attach to the instance role.
# This policy allows access to the s3 bucket for SQL Server Audit.
################################################################################

resource "aws_db_instance_role_association" "audit" {
  count                  = var.create && var.audit_bucket_name != null ? 1 : 0
  db_instance_identifier = module.db[count.index].db_instance_id
  feature_name           = "SQLSERVER_AUDIT"
  role_arn               = join("", aws_iam_role.audit.*.arn)
  depends_on = [
    aws_iam_role.audit
  ]
}

resource "aws_iam_role" "audit" {
  count              = var.create && var.audit_bucket_name != null ? 1 : 0
  name               = "s3-audit-data-${lower(var.instance_name)}"
  assume_role_policy = join("", data.aws_iam_policy_document.audit_trust.*.json)
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "audit" {
  count = var.create && var.audit_bucket_name != null ? 1 : 0
  role  = join("", aws_iam_role.audit.*.name)
  # The actions the role can execute
  policy_arn = join("", aws_iam_policy.audit.*.arn)
}

resource "aws_iam_policy" "audit" {
  count       = var.create && var.audit_bucket_name != null ? 1 : 0
  name        = "s3-audit-data-${lower(var.instance_name)}"
  description = "Terraform managed RDS Instance auditing policy."
  policy      = join("", data.aws_iam_policy_document.audit.*.json)
  tags        = var.tags
}

data "aws_iam_policy_document" "audit_trust" {
  count = var.create && var.audit_bucket_name != null ? 1 : 0
  statement {
    actions = [
      "sts:AssumeRole"
    ]

    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["rds.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "audit" {
  count = var.create && var.audit_bucket_name != null ? 1 : 0
  statement {
    actions = [
      "s3:ListAllMyBuckets",
    ]
    resources = [
      "*"
    ]
    effect = "Allow"
  }

  statement {
    actions = [
      "s3:ListBucket",
      "s3:GetBucketACL",
      "s3:GetBucketLocation",
    ]
    resources = [
      "arn:aws:s3:::${var.audit_bucket_name}"
    ]
    effect = "Allow"
  }

  statement {
    actions = [
      "s3:PutObject",
      "s3:ListMultipartUploadParts",
      "s3:AbortMultipartUpload",
    ]
    resources = [
      "arn:aws:s3:::${var.audit_bucket_name}/*"
    ]
    effect = "Allow"
  }
}

################################################################################
# This is the key for Transparent Data Encryption (TDE).
# If TDE is implemented, it must be the first option_name in the mssql_options
# parameter (var.mssql_options[0]["option_name"] == "TDE"),
# because splat var.mssql_options[*]["option_name"] == "TDE" does not work.
################################################################################

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

# # Hard coded to the primary region for SSO, as directed
data "aws_iam_roles" "tde_dse_sso" {
  name_regex  = "AWSReservedSSO_DataSystemsEngineer*"
  path_prefix = "/aws-reserved/sso.amazonaws.com/us-east-2/"
}

data "aws_iam_roles" "tde_automation" {
  name_regex = "TrueMarkDatabaseAutomation*"
}

# # The actual key definition
resource "aws_kms_key" "tde_key" {
  count       = var.create && var.mssql_options[0]["option_name"] == "TDE" ? 1 : 0
  description = "The KMS key assigned to the database master key."
  tags        = var.tags
  policy      = data.aws_iam_policy_document.tde_policy[count.index].json
}

# # The key alias, the way all other automation refers to it
resource "aws_kms_alias" "tde_key" {
  count         = var.create && var.mssql_options[0]["option_name"] == "TDE" ? 1 : 0
  name          = "alias/${var.instance_name}-key-encryption-key"
  target_key_id = aws_kms_key.tde_key[0].arn
}

# # The key policy grants administrative access to this key (the owner).
# # I'm not sure it's possible to define resources specific to this key only because
# # it becomes a circular reference.
data "aws_iam_policy_document" "tde_policy" {
  count = var.create && var.mssql_options[0]["option_name"] == "TDE" ? 1 : 0
  statement {
    actions = [
      "kms:*"
    ]
    resources = ["arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:key/*"]
    # Uncomment and get popcorn
    # resources = [ "${aws_kms_key.tde_key.arn}" ]
    principals {
      type = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
        "${tolist(data.aws_iam_roles.tde_dse_sso.arns)[0]}",
      "${tolist(data.aws_iam_roles.tde_automation.arns)[0]}"]
    }
  }
}

# The policy that defines what users can do
resource "aws_iam_policy" "tde_exec_policy" {
  count  = var.create && var.mssql_options[0]["option_name"] == "TDE" ? 1 : 0
  name   = "${var.instance_name}-key-encryption-key"
  tags   = var.tags
  policy = data.aws_iam_policy_document.tde_exec_policy[count.index].json
}

#
data "aws_iam_policy_document" "tde_exec_policy" {
  count = var.create && var.mssql_options[0]["option_name"] == "TDE" ? 1 : 0
  statement {
    actions = [
      "kms:*"
    ]
    resources = ["arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:key/*"]
    # resources = [aws_kms_key.tde_key[count.index].arn]
  }
}

resource "aws_iam_role_policy_attachment" "tde_exec_policy" {
  count = var.create && var.mssql_options[0]["option_name"] == "TDE" ? 1 : 0
  role  = join("", aws_iam_role.s3_data_archive.*.name)
  # The actions the role can execute
  policy_arn = join("", aws_iam_policy.tde_exec_policy[*].arn)
}



