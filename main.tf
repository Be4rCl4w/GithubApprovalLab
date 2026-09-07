terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

variable "location" {
  default = "northeurope"
}

variable "environment" {
  default = "lab"
}

# Resource Group
resource "azurerm_resource_group" "lab" {
  name     = "rg-security-lab-${var.environment}"
  location = var.location
}

# Virtual Network with Subnet
resource "azurerm_virtual_network" "lab" {
  name                = "vnet-lab-${var.environment}"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
}

resource "azurerm_subnet" "lab" {
  name                 = "subnet-lab-${var.environment}"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = ["10.0.1.0/24"]
}

# Network Security Group (Vulnerable Configuration)
resource "azurerm_network_security_group" "lab" {
  name                = "nsg-lab-${var.environment}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name

  # VULNERABLE: Allow all inbound traffic from anywhere
  security_rule {
    name                       = "AllowAllInbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # VULNERABLE: Allow all outbound traffic
  security_rule {
    name                       = "AllowAllOutbound"
    priority                   = 100
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "lab" {
  subnet_id                 = azurerm_subnet.lab.id
  network_security_group_id = azurerm_network_security_group.lab.id
}

# Storage Account (Vulnerable Configuration)
resource "azurerm_storage_account" "lab" {
  name                     = "stglabsec${substr(md5(azurerm_resource_group.lab.id), 0, 8)}"
  resource_group_name      = azurerm_resource_group.lab.name
  location                 = azurerm_resource_group.lab.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # VULNERABLE: HTTPS not enforced
  https_traffic_only_enabled = false

  # VULNERABLE: Public blob access allowed
  shared_access_key_enabled = true

  # VULNERABLE: No encryption at rest enforcement
  min_tls_version = "TLS1_0"
}

# Storage Containers (Vulnerable Configuration)
resource "azurerm_storage_container" "container1" {
  name                  = "container1"
  storage_account_name  = azurerm_storage_account.lab.name
  container_access_type = "blob" # VULNERABLE: Public blob access

  depends_on = [azurerm_storage_account.lab]
}

resource "azurerm_storage_container" "container2" {
  name                  = "container2"
  storage_account_name  = azurerm_storage_account.lab.name
  container_access_type = "blob" # VULNERABLE: Public blob access

  depends_on = [azurerm_storage_account.lab]
}

resource "azurerm_storage_container" "container3" {
  name                  = "container3"
  storage_account_name  = azurerm_storage_account.lab.name
  container_access_type = "blob" # VULNERABLE: Public blob access

  depends_on = [azurerm_storage_account.lab]
}

# Managed Identity
resource "azurerm_user_assigned_identity" "lab" {
  name                = "id-lab-${var.environment}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
}

# SQL Server (Vulnerable Configuration)
resource "azurerm_mssql_server" "lab" {
  name                         = "sql-lab-${substr(md5(azurerm_resource_group.lab.id), 0, 8)}-${var.environment}"
  resource_group_name          = azurerm_resource_group.lab.name
  location                     = azurerm_resource_group.lab.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "P@ssw0rd1234!" # VULNERABLE: Weak credentials stored

  # VULNERABLE: Public endpoint enabled without restriction
  public_network_access_enabled = true

  # VULNERABLE: No encryption enforced
  transparent_data_encryption_key_vault_key_id = null
}

# SQL Database
resource "azurerm_mssql_database" "lab" {
  name           = "sqldb-lab-${var.environment}"
  server_id      = azurerm_mssql_server.lab.id
  collation      = "SQL_Latin1_General_CP1_CI_AS"
  sku_name       = "Basic" # Most cost-effective option

}


# App Service Plan (Free tier)
resource "azurerm_app_service_plan" "lab" {
  name                = "plan-lab-${var.environment}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  kind                = "Linux"
  reserved            = true

  sku {
    tier = "Free"
    size = "F1"
  }
}

# App Service (Vulnerable Configuration)
resource "azurerm_app_service" "lab" {
  name                = "app-lab-${substr(md5(azurerm_resource_group.lab.id), 0, 8)}-${var.environment}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  app_service_plan_id = azurerm_app_service_plan.lab.id

  # VULNERABLE: HTTPS not enforced
  https_only = false

  app_settings = {
    # VULNERABLE: Sensitive data in app settings
    "CONNECTION_STRING" = "Server=tcp:${azurerm_mssql_server.lab.fully_qualified_domain_name},1433;Initial Catalog=${azurerm_mssql_database.lab.name};Persist Security Info=False;User ID=sqladmin;Password=P@ssw0rd1234!;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
    "STORAGE_ACCOUNT"   = azurerm_storage_account.lab.name
    "STORAGE_KEY"       = azurerm_storage_account.lab.primary_access_key # VULNERABLE: Exposed key
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.lab.id]
  }

  site_config {
    # VULNERABLE: No managed identity in use
    use_32_bit_worker_process = true

    # VULNERABLE: Remote debugging enabled
    remote_debugging_enabled = true
    remote_debugging_version = "VS2019"

    # VULNERABLE: Minimum TLS version not enforced
    min_tls_version = "1.0"

  }
}

# Network Interface for VM
resource "azurerm_network_interface" "lab" {
  name                = "nic-lab-${var.environment}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name

  ip_configuration {
    name                          = "testConfiguration"
    subnet_id                     = azurerm_subnet.lab.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.lab.id
  }
}

# Public IP for VM (Vulnerable: Exposed to internet)
resource "azurerm_public_ip" "lab" {
  name                = "pip-lab-${var.environment}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

# Virtual Machine (Vulnerable Configuration)
resource "azurerm_windows_virtual_machine" "lab" {
  name                = "vm-lab-${var.environment}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  size                = "Standard_B1s" # Most cost-effective
  network_interface_ids = [azurerm_network_interface.lab.id]

  # VULNERABLE: Weak credentials
  admin_username = "azureuser"
  admin_password = "P@ssw0rd1234!"

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-Datacenter"
    version   = "latest"
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.lab.id]
  }

  # VULNERABLE: Enable guest configuration disabled
  enable_automatic_updates = true
}

# NIC Association with NSG
resource "azurerm_network_interface_security_group_association" "lab" {
  network_interface_id      = azurerm_network_interface.lab.id
  network_security_group_id = azurerm_network_security_group.lab.id
}

# Role Assignment for Managed Identity to Storage Account (Overly Permissive)
resource "azurerm_role_assignment" "storage_owner" {
  scope              = azurerm_storage_account.lab.id
  role_definition_name = "Storage Blob Data Owner" # VULNERABLE: Too permissive
  principal_id       = azurerm_user_assigned_identity.lab.principal_id
}

# Role Assignment for Managed Identity to SQL Database
resource "azurerm_role_assignment" "sql_owner" {
  scope              = azurerm_mssql_server.lab.id
  role_definition_name = "SQL Server Contributor" # VULNERABLE: Too permissive
  principal_id       = azurerm_user_assigned_identity.lab.principal_id
}

# Outputs
output "storage_account_name" {
  value = azurerm_storage_account.lab.name
}

output "storage_account_primary_key" {
  value     = azurerm_storage_account.lab.primary_access_key
  sensitive = true
}

output "sql_server_fqdn" {
  value = azurerm_mssql_server.lab.fully_qualified_domain_name
}

output "app_service_url" {
  value = "https://${azurerm_app_service.lab.default_site_hostname}"
}

output "vm_public_ip" {
  value = azurerm_public_ip.lab.ip_address
}

output "managed_identity_id" {
  value = azurerm_user_assigned_identity.lab.id
}

output "managed_identity_principal_id" {
  value = azurerm_user_assigned_identity.lab.principal_id
}

output "virtual_network_id" {
  value = azurerm_virtual_network.lab.id
}

output "subnet_id" {
  value = azurerm_subnet.lab.id
}
