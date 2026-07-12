#!/bin/bash
# setup-dns.sh: Generate DNS records for a mailserver domain
# Supports manual entry, Route53, Cloudflare, and Bind zone file formats

set -e

DOMAIN="${1:?Domain required: $0 <domain> [provider]}"
PROVIDER="${2:-manual}"
SERVER_IP="${SERVER_IP:-mail.example.com}"

# Validate domain
if [[ ! "$DOMAIN" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$ ]]; then
    echo "Error: Invalid domain '$DOMAIN'" >&2
    exit 1
fi

echo "=== Mailserver DNS Setup for $DOMAIN ==="
echo "Provider: $PROVIDER"
echo ""

case "$PROVIDER" in
    manual)
        echo "Add the following records to your DNS provider:"
        echo ""
        echo "1. MX Record (Priority 10):"
        echo "   Name:   @"
        echo "   Value:  mail.$DOMAIN"
        echo ""
        echo "2. A Record:"
        echo "   Name:   mail"
        echo "   Value:  $SERVER_IP"
        echo ""
        echo "3. SPF Record (TXT):"
        echo "   Name:   @"
        echo "   Value:  v=spf1 ip4:$SERVER_IP ~all"
        echo ""
        echo "4. DMARC Policy (TXT):"
        echo "   Name:   _dmarc"
        echo "   Value:  v=DMARC1; p=quarantine; rua=mailto:dmarc@$DOMAIN"
        echo ""
        echo "5. DKIM (after running mailserverd):"
        echo "   Name:   default._domainkey"
        echo "   Value:  Run: mailserverd dkim generate $DOMAIN"
        echo "           and add the resulting TXT record"
        echo ""
        echo "Verification: dig MX $DOMAIN +short"
        echo "              dig TXT $DOMAIN +short"
        ;;
    route53)
        echo "AWS Route53 API format (save as records.json):"
        echo ""
        cat > /tmp/dns-records-route53.json <<EOF
{
  "Changes": [
    {
      "Action": "CREATE",
      "ResourceRecordSet": {
        "Name": "$DOMAIN",
        "Type": "MX",
        "TTL": 3600,
        "ResourceRecords": [
          {"Value": "10 mail.$DOMAIN"}
        ]
      }
    },
    {
      "Action": "CREATE",
      "ResourceRecordSet": {
        "Name": "mail.$DOMAIN",
        "Type": "A",
        "TTL": 3600,
        "ResourceRecords": [
          {"Value": "$SERVER_IP"}
        ]
      }
    },
    {
      "Action": "CREATE",
      "ResourceRecordSet": {
        "Name": "$DOMAIN",
        "Type": "TXT",
        "TTL": 3600,
        "ResourceRecords": [
          {"Value": "\"v=spf1 ip4:$SERVER_IP ~all\""}
        ]
      }
    },
    {
      "Action": "CREATE",
      "ResourceRecordSet": {
        "Name": "_dmarc.$DOMAIN",
        "Type": "TXT",
        "TTL": 3600,
        "ResourceRecords": [
          {"Value": "\"v=DMARC1; p=quarantine; rua=mailto:dmarc@$DOMAIN\""}
        ]
      }
    }
  ]
}
EOF
        cat /tmp/dns-records-route53.json
        echo ""
        echo "To apply:"
        echo "  ZONE_ID=\$(aws route53 list-hosted-zones-by-name --dns-name $DOMAIN --query 'HostedZones[0].Id' --output text)"
        echo "  aws route53 change-resource-record-sets --hosted-zone-id \$ZONE_ID --change-batch file:///tmp/dns-records-route53.json"
        ;;
    cloudflare)
        echo "Cloudflare API format (requires CF_API_TOKEN):"
        echo ""
        echo "# 1. Get zone ID:"
        echo "ZONE_ID=\$(curl -s -H \"Authorization: Bearer \$CF_API_TOKEN\" \\"
        echo "  \"https://api.cloudflare.com/client/v4/zones?name=$DOMAIN\" \\"
        echo "  | jq -r '.result[0].id')"
        echo ""
        echo "# 2. Create MX record:"
        echo "curl -X POST -H \"Authorization: Bearer \$CF_API_TOKEN\" \\"
        echo "  -H \"Content-Type: application/json\" \\"
        echo "  -d '{\"type\":\"MX\",\"name\":\"@\",\"content\":\"mail.$DOMAIN\",\"priority\":10,\"ttl\":3600}' \\"
        echo "  \"https://api.cloudflare.com/client/v4/zones/\$ZONE_ID/dns_records\""
        echo ""
        echo "# 3. Create A record:"
        echo "curl -X POST -H \"Authorization: Bearer \$CF_API_TOKEN\" \\"
        echo "  -H \"Content-Type: application/json\" \\"
        echo "  -d '{\"type\":\"A\",\"name\":\"mail\",\"content\":\"$SERVER_IP\",\"ttl\":3600}' \\"
        echo "  \"https://api.cloudflare.com/client/v4/zones/\$ZONE_ID/dns_records\""
        echo ""
        echo "# 4. Create SPF record:"
        echo "curl -X POST -H \"Authorization: Bearer \$CF_API_TOKEN\" \\"
        echo "  -H \"Content-Type: application/json\" \\"
        echo "  -d '{\"type\":\"TXT\",\"name\":\"@\",\"content\":\"v=spf1 ip4:$SERVER_IP ~all\",\"ttl\":3600}' \\"
        echo "  \"https://api.cloudflare.com/client/v4/zones/\$ZONE_ID/dns_records\""
        echo ""
        echo "# 5. Create DMARC record:"
        echo "curl -X POST -H \"Authorization: Bearer \$CF_API_TOKEN\" \\"
        echo "  -H \"Content-Type: application/json\" \\"
        echo "  -d '{\"type\":\"TXT\",\"name\":\"_dmarc\",\"content\":\"v=DMARC1; p=quarantine; rua=mailto:dmarc@$DOMAIN\",\"ttl\":3600}' \\"
        echo "  \"https://api.cloudflare.com/client/v4/zones/\$ZONE_ID/dns_records\""
        ;;
    bind)
        echo "BIND Zone File Format (add to named.conf):"
        echo ""
        cat > /tmp/$DOMAIN.zone <<EOF
\$ORIGIN $DOMAIN.
\$TTL 3600

@       IN SOA  ns1.$DOMAIN. hostmaster.$DOMAIN. (
                2026071201      ; serial
                3600            ; refresh
                1800            ; retry
                604800          ; expire
                86400 )         ; minimum

@       IN NS   ns1.$DOMAIN.
@       IN NS   ns2.$DOMAIN.

mail    IN A     $SERVER_IP
@       IN MX   10 mail.$DOMAIN.
@       IN TXT  "v=spf1 ip4:$SERVER_IP ~all"
_dmarc  IN TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@$DOMAIN"
EOF
        cat /tmp/$DOMAIN.zone
        echo ""
        echo "Saved to: /tmp/$DOMAIN.zone"
        ;;
    *)
        echo "Unknown provider: $PROVIDER" >&2
        echo "Supported: manual, route53, cloudflare, bind" >&2
        exit 1
        ;;
esac

echo ""
echo "=== Testing DNS Resolution ==="
echo "Once records are live (may take 5-15 min), verify with:"
echo "  dig MX $DOMAIN +short"
echo "  dig A mail.$DOMAIN +short"
echo "  dig TXT $DOMAIN +short"
echo ""
echo "Optional: Full propagation check at https://mxtoolbox.com/mxlookup.aspx?domain=$DOMAIN"
