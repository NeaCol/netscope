import base64
import os
import platform
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn
from netscope import __version__
from netscope.analyzer.latency import measure_latency, run_traceroute
from netscope.analyzer.topology import build_network_topology
from netscope.analyzer.traffic import analyze_traffic
from netscope.protocols.dissector import dissect_packet
from netscope.protocols.dns import benchmark_resolvers, query_dns
from netscope.protocols.pcap import generate_educational_pcap, parse_pcap_packets
from netscope.scanner.discovery import scan_subnet
from netscope.scanner.interfaces import get_default_gateway_and_ip, get_primary_interface, list_interfaces
from netscope.scanner.ports import scan_ports

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(
    title="NetScope API",
    description="Educational Network Diagnostic & Topology Backend",
    version=__version__,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class RawPacketRequest(BaseModel):
    hex_data: Optional[str] = None
    base64_data: Optional[str] = None


@app.get("/", response_class=HTMLResponse)
def index_page():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return HTMLResponse("<h1>NetScope Dashboard</h1><p>Static files not found.</p>")


@app.get("/style.css")
def get_style_css():
    return FileResponse(STATIC_DIR / "style.css", media_type="text/css")


@app.get("/app.js")
def get_app_js():
    return FileResponse(STATIC_DIR / "app.js", media_type="application/javascript")


@app.get("/api/status")
def get_system_status() -> Dict[str, Any]:
    primary = get_primary_interface()
    gw, local_ip = get_default_gateway_and_ip()
    return {
        "version": __version__,
        "platform": platform.platform(),
        "primary_interface": primary.name if primary else None,
        "local_ip": local_ip,
        "default_gateway": gw,
        "cidr": primary.cidr if primary else None,
    }


@app.get("/api/interfaces")
def get_interfaces() -> List[Dict[str, Any]]:
    return [nic.to_dict() for nic in list_interfaces()]


@app.get("/api/scan")
def scan_network(subnet: Optional[str] = None, threads: int = Query(40, ge=1, le=100)) -> List[Dict[str, Any]]:
    hosts = scan_subnet(cidr=subnet, max_threads=threads)
    return [h.to_dict() for h in hosts]


@app.get("/api/ports")
def scan_host_ports(host: str, ports: Optional[str] = None) -> List[Dict[str, Any]]:
    target_ports = None
    if ports:
        try:
            target_ports = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid ports parameter")
    results = scan_ports(host=host, ports=target_ports)
    return [p.to_dict() for p in results]


@app.get("/api/dns")
def get_dns(
    domain: str = Query("example.com"),
    type: str = Query("A"),
    server: str = Query("1.1.1.1"),
    benchmark: bool = Query(False),
) -> Dict[str, Any]:
    if benchmark:
        bench = benchmark_resolvers(domain=domain)
        return {"domain": domain, "benchmark": [b.to_dict() for b in bench]}
    result = query_dns(domain=domain, record_type=type, server=server)
    return result.to_dict()


@app.get("/api/ping")
def ping_target(target: str = Query("1.1.1.1"), count: int = Query(5, ge=1, le=20)) -> Dict[str, Any]:
    stats = measure_latency(host=target, count=count)
    return stats.to_dict()


@app.get("/api/trace")
def trace_target(target: str = Query("1.1.1.1"), max_hops: int = Query(15, ge=1, le=30)) -> List[Dict[str, Any]]:
    hops = run_traceroute(target=target, max_hops=max_hops)
    return [h.to_dict() for h in hops]


@app.get("/api/topology")
def get_topology() -> Dict[str, Any]:
    graph = build_network_topology()
    return graph.to_dict()


@app.post("/api/analyze-packet")
def analyze_packet_payload(req: RawPacketRequest) -> Dict[str, Any]:
    raw_bytes = b""
    if req.hex_data:
        clean = "".join(req.hex_data.split())
        try:
            raw_bytes = bytes.fromhex(clean)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid hex string")
    elif req.base64_data:
        try:
            raw_bytes = base64.b64decode(req.base64_data)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid base64 payload")
    else:
        raise HTTPException(status_code=400, detail="Provide hex_data or base64_data")

    pkt = dissect_packet(raw_bytes)
    return pkt.to_dict()


@app.get("/api/sample-pcap")
def get_sample_pcap_analysis() -> Dict[str, Any]:
    pcap_data = generate_educational_pcap()
    packets = parse_pcap_packets(pcap_data)
    traffic_report = analyze_traffic(packets)
    return {
        "report": traffic_report.to_dict(),
        "packets": [p.to_dict() for p in packets],
    }


def start_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    uvicorn.run(app, host=host, port=port, log_level="info")
