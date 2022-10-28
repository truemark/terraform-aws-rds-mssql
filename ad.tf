# TODO: Make the domain id truly optional. Currently this module will
# create all objects required to integrate AD with the instance, but
# the instance will not be associated with the role. 

# All objects required to hook this db up to Active Directory
resource "aws_db_instance_role_association" "ad" {
  count                  = var.domain_id == "" ? 0 : 1
  db_instance_identifier = module.db.db_instance_id
  role_arn               = aws_iam_role.ad[0].arn
  feature_name           = "Directory Service"
}

resource "aws_iam_role" "ad" {
  count              = var.domain_id == "" ? 0 : 1
  name               = "${lower(var.instance_name)}-active-directory"
  description        = "Role used by RDS for Active Directory authentication and authorization"
  assume_role_policy = data.aws_iam_policy_document.rds_assume_role.json
}

resource "aws_iam_role_policy_attachment" "ad" {
  count = var.domain_id == "" ? 0 : 1
  role  = aws_iam_role.ad[0].name
  # The actions the role can execute
  policy_arn = data.aws_iam_policy.ad.arn
  depends_on = [
    aws_iam_role.ad
  ]
}

data "aws_iam_policy" "ad" {
  arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSDirectoryServiceAccess"
}

data "aws_iam_policy_document" "rds_assume_role" {
  statement {
    sid = "AssumeRole"

    actions = [
      "sts:AssumeRole",
    ]

    principals {
      type        = "Service"
      identifiers = ["rds.amazonaws.com"]
    }
  }
}
