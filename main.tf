provider "aws" {
  region = "us-east-1"
}

############################
# VPC
############################
resource "aws_vpc" "devopsshack_vpc" {
  cidr_block = "10.0.0.0/16"
  tags = { Name = "devopsshack-vpc" }
}

resource "aws_subnet" "devopsshack_subnet" {
  count                   = 2
  vpc_id                  = aws_vpc.devopsshack_vpc.id
  cidr_block              = cidrsubnet(aws_vpc.devopsshack_vpc.cidr_block, 8, count.index)
  availability_zone       = element(["us-east-1a", "us-east-1b"], count.index)
  map_public_ip_on_launch = true
  tags = { Name = "devopsshack-subnet-${count.index}" }
}

resource "aws_internet_gateway" "devopsshack_igw" {
  vpc_id = aws_vpc.devopsshack_vpc.id
}

resource "aws_route_table" "devopsshack_rt" {
  vpc_id = aws_vpc.devopsshack_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.devopsshack_igw.id
  }
}

resource "aws_route_table_association" "rt_assoc" {
  count          = 2
  subnet_id      = aws_subnet.devopsshack_subnet[count.index].id
  route_table_id = aws_route_table.devopsshack_rt.id
}

############################
# SECURITY GROUPS
############################
resource "aws_security_group" "cluster_sg" {
  vpc_id = aws_vpc.devopsshack_vpc.id
  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "node_sg" {
  vpc_id = aws_vpc.devopsshack_vpc.id
  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

############################
# IAM ROLES
############################
resource "aws_iam_role" "eks_cluster_role" {
  name = "devopsshack-eks-cluster-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role" "node_role" {
  name = "devopsshack-node-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "node_worker" {
  role       = aws_iam_role.node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "node_cni" {
  role       = aws_iam_role.node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "node_ecr" {
  role       = aws_iam_role.node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

############################
# EKS CLUSTER
############################
resource "aws_eks_cluster" "eks" {
  name     = "devopsshack-cluster"
  role_arn = aws_iam_role.eks_cluster_role.arn
  vpc_config {
    subnet_ids         = aws_subnet.devopsshack_subnet[*].id
    security_group_ids = [aws_security_group.cluster_sg.id]
  }
}

resource "aws_eks_node_group" "node_group" {
  cluster_name    = aws_eks_cluster.eks.name
  node_group_name = "devopsshack-ng"
  node_role_arn   = aws_iam_role.node_role.arn
  subnet_ids      = aws_subnet.devopsshack_subnet[*].id
  instance_types  = ["t2.medium"]
  scaling_config {
    desired_size = 3
    min_size     = 3
    max_size     = 3
  }
}

############################
# OIDC + LOCALS
############################
data "aws_eks_cluster" "eks" {
  name = aws_eks_cluster.eks.name
}

resource "aws_iam_openid_connect_provider" "eks" {
  url             = data.aws_eks_cluster.eks.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["9e99a48a9960b14926bb7f3b02e22da0ecdcc1d4"]
}

locals {
  oidc_sub_key = "${replace(data.aws_eks_cluster.eks.identity[0].oidc[0].issuer, "https://", "")}:sub"
}

############################
# VPC CNI (IRSA)
############################
resource "aws_iam_role" "vpc_cni_irsa" {
  name = "devopsshack-vpc-cni-irsa"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          local.oidc_sub_key = "system:serviceaccount:kube-system:aws-node"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "vpc_cni_attach" {
  role       = aws_iam_role.vpc_cni_irsa.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_eks_addon" "vpc_cni" {
  cluster_name             = aws_eks_cluster.eks.name
  addon_name               = "vpc-cni"
  service_account_role_arn = aws_iam_role.vpc_cni_irsa.arn
}

############################
# CORE ADDONS
############################
resource "aws_eks_addon" "coredns" {
  cluster_name = aws_eks_cluster.eks.name
  addon_name   = "coredns"
}

resource "aws_eks_addon" "kube_proxy" {
  cluster_name = aws_eks_cluster.eks.name
  addon_name   = "kube-proxy"
}

############################
# EBS CSI DRIVER (IRSA)
############################
resource "aws_iam_role" "ebs_csi_irsa" {
  name = "devopsshack-ebs-csi-irsa"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          local.oidc_sub_key = "system:serviceaccount:kube-system:ebs-csi-controller-sa"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ebs_csi_attach" {
  role       = aws_iam_role.ebs_csi_irsa.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

resource "aws_eks_addon" "ebs_csi" {
  cluster_name             = aws_eks_cluster.eks.name
  addon_name               = "aws-ebs-csi-driver"
  service_account_role_arn = aws_iam_role.ebs_csi_irsa.arn
  depends_on = [aws_eks_node_group.node_group]
}
