module "db" {

  source  = "terraform-aws-modules/rds/aws"
  version = "5.1.0"

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
  parameter_group_name                = aws_db_parameter_group.db_parameter_group.name
  password                            = random_password.root_password.result
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
  vpc_security_group_ids              = [aws_security_group.db_security_group.id]
}

resource "aws_db_parameter_group" "db_parameter_group" {
  name_prefix = var.instance_name
  description = "Terraform managed parameter group for ${var.instance_name}"
  family      = var.parameter_group_family
  tags        = var.tags
  dynamic "parameter" {
    for_each = { for a in var.db_parameters : a => a }
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
  count       = var.store_master_password_as_secret ? 1 : 0
  name_prefix = "database/${var.instance_name}/master-"
  description = "Master password for ${var.username} in ${var.instance_name}"
  tags        = var.tags
}

resource "aws_secretsmanager_secret_version" "db" {
  count     = var.store_master_password_as_secret ? 1 : 0
  secret_id = aws_secretsmanager_secret.db[count.index].id
  secret_string = jsonencode({
    "username"       = "root"
    "password"       = random_password.root_password.result
    "host"           = module.db.db_instance_address
    "port"           = module.db.db_instance_port
    "dbname"         = "master"
    "connect_string" = join("", concat(["${module.db.db_instance_address}"], [","], [module.db.db_instance_port]))
    "engine"         = "mssql"
  })
}

resource "random_password" "root_password" {
  length  = var.random_password_length
  special = false
  numeric = false
}

data "aws_secretsmanager_secret_version" "db" {
  # There will only ever be one password here. Hard coding the index.
  secret_id  = aws_secretsmanager_secret.db[0].id
  depends_on = [aws_secretsmanager_secret_version.db]
}

#-----------------------------------------------------------------------------

resource "aws_security_group" "db_security_group" {
  name   = var.instance_name
  vpc_id = var.vpc_id
  tags   = var.tags

  ingress {
    from_port   = var.port
    to_port     = var.port
    protocol    = "tcp"
    cidr_blocks = var.ingress_cidrs
  }
}

#-----------------------------------------------------------------------------
# Define the option group explicitly so we can implement SQLSERVER_BACKUP_RESTORE
resource "aws_db_option_group" "mssql_rds" {
  count                    = 1
  name_prefix              = var.instance_name
  option_group_description = "MSSQL RDS Option Group managed by Terraform."
  engine_name              = var.engine
  major_engine_version     = var.major_engine_version

  dynamic "option" {
    for_each = { for a in aws_iam_role.s3_data_archive.*.arn : a => a }
    content {
      option_name = "SQLSERVER_BACKUP_RESTORE"
      option_settings {
        name  = "IAM_ROLE_ARN"
        value = option.value
      }
    }
  }
}

################################################################################
# Create an IAM role to allow access to the s3 data archive bucket
################################################################################

resource "aws_db_instance_role_association" "s3_data_archive" {
  count                  = var.archive_bucket_name != null ? 1 : 0
  db_instance_identifier = module.db.db_instance_id
  feature_name           = "S3_INTEGRATION"
  role_arn               = join("", aws_iam_role.s3_data_archive.*.arn)
}

resource "aws_iam_role" "s3_data_archive" {
  count              = var.archive_bucket_name != null ? 1 : 0
  name               = "s3-data-archive-${lower(var.instance_name)}"
  assume_role_policy = join("", data.aws_iam_policy_document.assume_s3_data_archive_role_policy.*.json)
}

resource "aws_iam_role_policy_attachment" "s3_data_archive" {
  count = var.archive_bucket_name != null ? 1 : 0
  role  = join("", aws_iam_role.s3_data_archive.*.name)
  # The actions the role can execute
  policy_arn = join("", aws_iam_policy.s3_data_archive.*.arn)
}

resource "aws_iam_policy" "s3_data_archive" {
  count       = var.archive_bucket_name != null ? 1 : 0
  name        = "s3-data-archive-${lower(var.instance_name)}"
  description = "Terraform managed RDS Instance policy."
  policy      = join("", data.aws_iam_policy_document.exec_s3_data_archive.*.json)
}

data "aws_iam_policy_document" "assume_s3_data_archive_role_policy" {
  count = var.archive_bucket_name != null ? 1 : 0
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
  count = var.archive_bucket_name != null ? 1 : 0
  statement {
    actions = [
      "s3:ListBucket",
      "s3:GetBucketLocation"
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
      "s3:AbortMultipartUpload",
    ]
    resources = [
      "arn:aws:s3:::${var.archive_bucket_name}/*"
    ]
    effect = "Allow"
  }

  dynamic "statement" {
    for_each = {for a in [var.kms_key_id]: a => a}
    content {
      actions = [
        "kms:Decrypt",
        "kms:Encrypt"
      ]
      resources = [
        statement.value
      ]
      effect = "Allow"
    }
  }
}
