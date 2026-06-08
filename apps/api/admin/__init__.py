# WebHound — apps/api/admin/
# Internal developer/operator CLI tools. NOT mounted on any HTTP surface and
# NOT shipped to customers. Authorization = shell/deploy access to the API or
# worker environment (run via `railway run` / inside the container). Every
# action is audit-logged by the underlying service (services/admin_scan.py).
