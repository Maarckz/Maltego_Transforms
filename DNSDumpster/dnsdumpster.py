import json
import re
import time
import base64
import argparse
from typing import Dict, List, Any, Optional, Tuple

import requests
from bs4 import BeautifulSoup


class DNSDumpsterParser:
    #############################################
    ## Inicialização / sessão / headers ##
    #############################################
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.session = requests.Session()

        self.base_url = "https://api.dnsdumpster.com/htmld/"
        self.home_url = "https://dnsdumpster.com/"

        self.ua = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0"

        self.home_headers = {
            "User-Agent": self.ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3",
            "Connection": "keep-alive",
        }

        self.api_headers_base = {
            "User-Agent": self.ua,
            "Accept": "*/*",
            "Referer": self.home_url,
            "Origin": "https://dnsdumpster.com",
            "HX-Request": "true",
            "HX-Target": "results",
            "HX-Current-URL": self.home_url,
            "Content-Type": "application/x-www-form-urlencoded",
        }

        self._auth_token: Optional[str] = None
        self._auth_exp: Optional[int] = None

    #############################################
    ## Decode JWT sem validação ##
    #############################################
    def _decode_jwt_no_verify(self, token: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("JWT inválido")

        def _b64url_decode(s: str) -> bytes:
            pad = "=" * ((4 - (len(s) % 4)) % 4)
            return base64.urlsafe_b64decode(s + pad)

        header = json.loads(_b64url_decode(parts[0]).decode())
        payload = json.loads(_b64url_decode(parts[1]).decode())
        return header, payload

    #############################################
    ## Busca token no HTML da home ##
    #############################################
    def _fetch_auth_token_from_home(self) -> Tuple[str, Optional[int]]:
        r = self.session.get(self.home_url, headers=self.home_headers, timeout=self.timeout)
        r.raise_for_status()

        m = re.search(
            r"(eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)",
            r.text,
        )
        if not m:
            raise RuntimeError("JWT não encontrado no HTML")

        token = m.group(1)

        exp = None
        try:
            _, payload = self._decode_jwt_no_verify(token)
            exp = int(payload.get("exp")) if "exp" in payload else None
        except Exception:
            pass

        return token, exp

    #############################################
    ## Garante token válido ##
    #############################################
    def _ensure_auth(self, margin: int = 60) -> None:
        now = int(time.time())
        if self._auth_token and self._auth_exp:
            if now < (self._auth_exp - margin):
                return

        self._auth_token, self._auth_exp = self._fetch_auth_token_from_home()

    #############################################
    ## Consulta domínio ##
    #############################################
    def query_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        self._ensure_auth()

        headers = dict(self.api_headers_base)
        headers["Authorization"] = self._auth_token

        response = self.session.post(
            self.base_url,
            headers=headers,
            data={"target": domain},
            timeout=self.timeout,
        )

        if response.status_code in (401, 403):
            self._auth_token = None
            self._auth_exp = None
            self._ensure_auth()
            headers["Authorization"] = self._auth_token
            response = self.session.post(
                self.base_url,
                headers=headers,
                data={"target": domain},
                timeout=self.timeout,
            )

        if response.status_code != 200:
            return None

        soup = BeautifulSoup(response.text, "html.parser")

        return {
            "domain": domain,
            "statistics": self._extract_statistics(soup),
            "a_records": self._extract_a_records(soup),
            "mx_records": self._extract_mx_records(soup),
            "ns_records": self._extract_ns_records(soup),
            "txt_records": self._extract_txt_records(soup),
        }

    #############################################
    ## Extractors ##
    #############################################
    def _extract_statistics(self, soup: BeautifulSoup) -> Dict[str, Any]:
        stats: Dict[str, Any] = {}
        for sid, key in [
            ("map-data", "locations"),
            ("asn-data", "asn_data"),
            ("service-data", "service_data"),
        ]:
            tag = soup.find("script", id=sid)
            if tag and tag.string:
                raw = tag.string.strip()
                if raw.startswith("{") and raw.endswith("}"):
                    try:
                        stats[key] = json.loads(raw)
                    except Exception:
                        pass
        return stats

    def _extract_a_records(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        records = []
        table = soup.find("table", id="a_rec_table")
        if not table:
            return records
        for row in table.find_all("tr")[1:]:
            cols = row.find_all("td")
            if len(cols) >= 7:
                rec = self._parse_record_row(cols)
                if rec:
                    records.append(rec)
        return records

    def _extract_mx_records(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        records = []
        header = soup.find("p", string=re.compile(r"MX Records"))
        if not header:
            return records
        table = header.find_next("table")
        if not table:
            return records
        for row in table.find_all("tr")[1:]:
            cols = row.find_all("td")
            if len(cols) >= 6:
                rec = self._parse_record_row(cols[:6])
                if rec:
                    records.append(rec)
        return records

    def _extract_ns_records(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        records = []
        header = soup.find("p", string=re.compile(r"NS Records"))
        if not header:
            return records
        table = header.find_next("table")
        if not table:
            return records
        for row in table.find_all("tr")[1:]:
            cols = row.find_all("td")
            if len(cols) >= 6:
                rec = self._parse_record_row(cols[:6])
                if rec:
                    records.append(rec)
        return records

    def _extract_txt_records(self, soup: BeautifulSoup) -> List[str]:
        records = []
        header = soup.find("p", string=re.compile(r"TXT Records"))
        if not header:
            return records
        table = header.find_next("table")
        if not table:
            return records
        for row in table.find_all("tr"):
            td = row.find("td")
            if td:
                records.append(td.get_text().strip().replace("&#34;", '"').strip('"'))
        return records

    #############################################
    ## Parse de linha ##
    #############################################
    def _parse_record_row(self, cols: List) -> Optional[Dict[str, Any]]:
        try:
            host = cols[0].get_text().strip()

            ip_td = cols[1]
            ip_lines = [x.strip() for x in ip_td.get_text().split("\n") if x.strip()]
            ip = ip_lines[0]

            reverse_dns = None
            span = ip_td.find("span", class_="xs-text")
            if span:
                reverse_dns = span.get_text().strip()

            asn_text = cols[2].get_text()
            asn_match = re.search(r"ASN:(\d+)", asn_text)
            asn_number = int(asn_match.group(1)) if asn_match else None
            cidr_match = re.search(r"(\d+\.\d+\.\d+\.\d+/\d+)", asn_text)
            cidr = cidr_match.group(1) if cidr_match else None

            asn_lines = [x.strip() for x in cols[3].get_text().split("\n") if x.strip()]
            asn_name = asn_lines[0] if asn_lines else ""
            country = asn_lines[1] if len(asn_lines) > 1 else None

            return {
                "host": host,
                "ip": ip,
                "reverse_dns": reverse_dns,
                "asn": {
                    "number": asn_number,
                    "cidr": cidr,
                    "name": asn_name,
                    "country": country,
                },
            }
        except Exception:
            return None


#############################################
## CLI ##
#############################################
def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Domínio alvo")
    args = parser.parse_args()

    dns = DNSDumpsterParser()
    result = dns.query_domain(args.target)

    if result:
        print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
