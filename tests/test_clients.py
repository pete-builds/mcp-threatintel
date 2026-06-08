"""Client parse/format tests. No real network: the HTTP layer is mocked."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mcp_threatintel.clients.cisa import CisaClient  # noqa: E402


@pytest.mark.asyncio
async def test_cisa_shapes_kev_catalog(monkeypatch):
    """get_kev_catalog maps the raw CISA payload to the cache row schema."""
    raw = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-0001",
                "vendorProject": "Acme",
                "product": "Widget",
                "vulnerabilityName": "Acme Widget RCE",
                "shortDescription": "Remote code execution.",
                "dateAdded": "2024-01-02",
                "dueDate": "2024-01-23",
                "knownRansomwareCampaignUse": "Known",
                "notes": "patch now",
            },
            # Entry with no cveID must be dropped.
            {"vendorProject": "NoCve"},
        ]
    }

    client = CisaClient()

    async def fake_get(path, params=None):
        return raw

    monkeypatch.setattr(client, "get", fake_get)

    rows = await client.get_kev_catalog()
    await client.close()

    assert len(rows) == 1
    row = rows[0]
    assert row["cve_id"] == "CVE-2024-0001"
    assert row["vendor"] == "Acme"
    assert row["product"] == "Widget"
    assert row["vulnerability_name"] == "Acme Widget RCE"
    assert row["description"] == "Remote code execution."
    assert row["known_ransomware"] == "Known"
    assert "raw_json" in row
