#!/usr/bin/env python3
"""
LDAP Monitoring Diagrams
Professional diagrams using AWS icons for semantic accuracy
Generic LDAP monitoring setup applicable to any environment
"""

from diagrams import Diagram, Cluster, Edge

# AWS icons - semantically accurate for each component function
from diagrams.aws.compute import EC2Instance as Client  # Enterprise agents
from diagrams.aws.security import DirectoryService as LDAPService  # LDAP servers
from diagrams.aws.management import Cloudwatch as MonitoringService  # Monitoring SaaS
from diagrams.aws.security import Inspector as InspectorService  # Validation/inspection services
from diagrams.aws.security import CertificateManager as CertService  # Certificate services
from diagrams.aws.security import Guardduty as SecurityService  # Security validation
from diagrams.aws.management import Cloudtrail as AuditService  # Audit/compliance services
from diagrams.aws.network import VPC as Network, InternetGateway as Router
from diagrams.aws.security import WAF as Firewall  # Network security
from diagrams.aws.network import Route53 as DNS

# Additional AWS icons for specific functions
from diagrams.programming.language import JavaScript

def create_architecture():
    """Create LDAP monitoring architecture diagram"""
    
    with Diagram("ThousandEyes LDAP Monitoring Architecture", 
                 show=False, 
                 direction="TB",
                 filename="output/ldap_monitoring_architecture"):
        
        # ThousandEyes SaaS - monitoring service
        te_saas = MonitoringService("ThousandEyes SaaS\nControl Plane\n:443/HTTPS")
        
        # Regional Clusters
        with Cluster("EMEA Region"):
            with Cluster("Enterprise Agents"):
                emea_agent1 = Client("Agent ag-123456\n(Monitoring Client)")
                emea_agent2 = Client("Agent ag-123457\n(Monitoring Client)")
                emea_agents = [emea_agent1, emea_agent2]
            
            emea_firewall = Firewall("Corporate Firewall\nEMEA")
            
            with Cluster("LDAP Servers"):
                emea_ldap1 = LDAPService("ldap-emea-01.corp.com\n:636/LDAPS")
                emea_ldap2 = LDAPService("ldap-emea-02.corp.com\n:636/LDAPS")
                emea_ldaps = [emea_ldap1, emea_ldap2]
        
        with Cluster("AMER Region"):
            with Cluster("Enterprise Agents"):
                amer_agent1 = Client("Agent ag-234567\n(Monitoring Client)")
                amer_agent2 = Client("Agent ag-234568\n(Monitoring Client)")
                amer_agents = [amer_agent1, amer_agent2]
            
            amer_firewall = Firewall("Corporate Firewall\nAMER")
            
            with Cluster("LDAP Servers"):
                amer_ldap1 = LDAPService("ldap-amer-01.corp.com\n:636/LDAPS")
                amer_ldap2 = LDAPService("ldap-amer-02.corp.com\n:636/LDAPS")
                amer_ldaps = [amer_ldap1, amer_ldap2]
        
        with Cluster("APAC Region"):
            with Cluster("Enterprise Agents"):
                apac_agent1 = Client("Agent ag-345678\n(Monitoring Client)")
                apac_agent2 = Client("Agent ag-345679\n(Monitoring Client)")
                apac_agents = [apac_agent1, apac_agent2]
            
            apac_firewall = Firewall("Corporate Firewall\nAPAC")
            
            with Cluster("LDAP Servers"):
                apac_ldap1 = LDAPService("ldap-apac-01.corp.com\n:636/LDAPS")
                apac_ldap2 = LDAPService("ldap-apac-02.corp.com\n:636/LDAPS")
                apac_ldaps = [apac_ldap1, apac_ldap2]
        
        # Control plane connections
        for agent in emea_agents + amer_agents + apac_agents:
            agent >> Edge(style="dotted", label="443/HTTPS\nHeartbeat & Config") >> te_saas
        
        # Regional monitoring connections
        for agent in emea_agents:
            agent >> Edge(label="636/LDAPS\nMonitoring", color="red") >> emea_firewall
        emea_firewall >> Edge(color="red") >> emea_ldaps
        
        for agent in amer_agents:
            agent >> Edge(label="636/LDAPS\nMonitoring", color="red") >> amer_firewall
        amer_firewall >> Edge(color="red") >> amer_ldaps
        
        for agent in apac_agents:
            agent >> Edge(label="636/LDAPS\nMonitoring", color="red") >> apac_firewall
        apac_firewall >> Edge(color="red") >> apac_ldaps

def create_coverage():
    """Create coverage diagram"""
    
    with Diagram("LDAP Monitoring Coverage - Multi-Layer Validation", 
                 show=False, 
                 direction="TB",
                 filename="output/ldap_monitoring_coverage"):
        
        # Source - monitoring client
        agent = Client("ThousandEyes\nEnterprise Agent\n(Monitoring Client)")
        
        # Monitoring Script
        script = JavaScript("ldap-monitor.js\nTransaction Script")
        
        # Validation Layers with specific security services
        with Cluster("Layer 1: Network Connectivity"):
            tcp_check = Network("TCP Socket\nConnection")
            firewall_check = Firewall("Firewall\nRule Validation")
            routing_check = Router("Network Path\nIntegrity")
            
            network_metrics = MonitoringService("Network Metrics:\n• Connection Time\n• Routing Latency\n• Packet Loss")
        
        with Cluster("Layer 2: Security & Encryption"):
            tls_handshake = SecurityService("TLS Handshake\nValidation")
            cert_validation = CertService("Certificate Chain\nVerification")
            protocol_check = SecurityService("Protocol Compliance\nTLS 1.2+")
            
            security_metrics = SecurityService("Security Metrics:\n• Certificate Expiry\n• TLS Version\n• Cipher Strength")
        
        with Cluster("Layer 3: Application Service"):
            bind_operation = LDAPService("LDAP Bind\nAuthentication")
            search_operation = LDAPService("Directory Search\nRoot DSE Query")
            protocol_compliance = InspectorService("LDAPv3 Protocol\nCompliance")
            
            service_metrics = InspectorService("Service Metrics:\n• Bind Success Rate\n• Search Response\n• Error Codes")
        
        with Cluster("Layer 4: Performance Monitoring"):
            response_time = MonitoringService("Response Time\nMonitoring")
            threshold_check = InspectorService("Threshold\nValidation")
            sla_compliance = AuditService("SLA Compliance\nTracking")
            
            performance_metrics = MonitoringService("Performance Metrics:\n• <300ms Threshold\n• 99.9% Availability\n• Regional Latency")
        
        # Target - LDAP server
        ldap_server = LDAPService("LDAP Server\n:636/LDAPS")
        
        # Flow connections
        agent >> Edge(label="Execute") >> script
        script >> Edge(label="Test") >> ldap_server
        
        # Layer connections
        script >> Edge(label="1. TCP Connect", color="blue") >> tcp_check
        tcp_check >> Edge(color="blue") >> firewall_check
        firewall_check >> Edge(color="blue") >> routing_check
        routing_check >> Edge(color="blue") >> network_metrics
        
        script >> Edge(label="2. TLS Handshake", color="green") >> tls_handshake
        tls_handshake >> Edge(color="green") >> cert_validation
        cert_validation >> Edge(color="green") >> protocol_check
        protocol_check >> Edge(color="green") >> security_metrics
        
        script >> Edge(label="3. LDAP Operations", color="orange") >> bind_operation
        bind_operation >> Edge(color="orange") >> search_operation
        search_operation >> Edge(color="orange") >> protocol_compliance
        protocol_compliance >> Edge(color="orange") >> service_metrics
        
        script >> Edge(label="4. Performance Analysis", color="purple") >> response_time
        response_time >> Edge(color="purple") >> threshold_check
        threshold_check >> Edge(color="purple") >> sla_compliance
        sla_compliance >> Edge(color="purple") >> performance_metrics

def create_validation_matrix():
    """Create validation matrix diagram"""
    
    with Diagram("LDAP Monitoring Validation Matrix", 
                 show=False, 
                 direction="TB",
                 filename="output/validation_matrix"):
        
        with Cluster("Network Validation ✓"):
            net_items = [
                Network("TCP Port 636\nReachability"),
                Firewall("Firewall Rule\nCompliance"),
                MonitoringService("Network Latency\nMeasurement")
            ]
        
        with Cluster("Security Validation ✓"):
            sec_items = [
                CertService("Certificate\nExpiry Check"),
                CertService("CA Chain\nValidation"),
                SecurityService("TLS 1.2+\nEnforcement")
            ]
        
        with Cluster("Service Validation ✓"):
            svc_items = [
                LDAPService("Authentication\nBind Test"),
                LDAPService("Directory\nSearch Query"),
                InspectorService("Protocol\nCompliance")
            ]
        
        with Cluster("Performance Validation ✓"):
            perf_items = [
                MonitoringService("Response Time\n<300ms"),
                MonitoringService("Availability\n99.9%"),
                MonitoringService("Latency\nMonitoring")
            ]
        
        # Central monitoring engine
        monitor = MonitoringService("ldap-monitor.js\nValidation Service")
        
        # Connections
        for item in net_items:
            monitor >> Edge(color="blue") >> item
        
        for item in sec_items:
            monitor >> Edge(color="green") >> item
        
        for item in svc_items:
            monitor >> Edge(color="orange") >> item
        
        for item in perf_items:
            monitor >> Edge(color="purple") >> item

def create_timeline():
    """Create timeline diagram"""
    
    with Diagram("LDAP Monitoring Test Sequence", 
                 show=False, 
                 direction="LR",
                 filename="output/monitoring_timeline"):
        
        # Timeline steps
        step1 = Network("1. TCP Connection\nEstablishment\n(Network Layer)")
        step2 = SecurityService("2. TLS Handshake\n& Certificate\n(Security Layer)")
        step3 = LDAPService("3. LDAP Bind\nAuthentication\n(Directory Layer)")
        step4 = LDAPService("4. Directory Search\nRoot DSE Query\n(Service Layer)")
        step5 = MonitoringService("5. Performance\nValidation\n(Monitoring Layer)")
        
        # Timing annotations
        timing1 = MonitoringService("Baseline: <100ms")
        timing2 = MonitoringService("Threshold: <300ms")
        timing3 = MonitoringService("Threshold: <300ms")
        timing4 = MonitoringService("Threshold: <300ms")
        timing5 = MonitoringService("Total: <1000ms")
        
        # Sequential flow
        step1 >> Edge(label="Success") >> step2
        step2 >> Edge(label="Valid Cert") >> step3
        step3 >> Edge(label="Auth OK") >> step4
        step4 >> Edge(label="Data Retrieved") >> step5
        
        # Timing connections
        step1 >> Edge(style="dotted", color="red") >> timing1
        step2 >> Edge(style="dotted", color="red") >> timing2
        step3 >> Edge(style="dotted", color="red") >> timing3
        step4 >> Edge(style="dotted", color="red") >> timing4
        step5 >> Edge(style="dotted", color="red") >> timing5

def create_firewall_rules():
    """Create firewall rules diagram"""
    
    with Diagram("Required Firewall Rules", 
                 show=False, 
                 direction="LR",
                 filename="output/firewall_rules"):
        
        # Source networks
        with Cluster("Enterprise Agent Subnets"):
            agent_subnet = Network("Agent Networks\n(Per Region)")
        
        # Firewall
        firewall = Firewall("Corporate Firewall")
        
        # Destinations
        with Cluster("Allowed Destinations"):
            te_dest = MonitoringService("ThousandEyes SaaS\n*.thousandeyes.com\n443/HTTPS\nOutbound Only")
            ldap_dest = LDAPService("LDAP Directory Servers\n636/LDAPS\nOutbound Only")
        
        # Rules
        agent_subnet >> Edge(label="Rule 1: Control Plane", color="blue") >> firewall
        firewall >> Edge(label="443/HTTPS", color="blue") >> te_dest
        
        agent_subnet >> Edge(label="Rule 2: LDAP Monitoring", color="red") >> firewall
        firewall >> Edge(label="636/LDAPS", color="red") >> ldap_dest

if __name__ == "__main__":
    print("🚀 Generating LDAP monitoring diagrams...")
    print("✅ Using AWS icons for semantic accuracy")
    print("✅ Clean and professional appearance")
    print("✅ Generic LDAP monitoring setup")
    
    # Create output directory
    import os
    os.makedirs("output", exist_ok=True)
    
    create_architecture()
    print("✅ Architecture diagram created")
    
    create_coverage()
    print("✅ Coverage diagram created")
    
    create_validation_matrix()
    print("✅ Validation matrix created")
    
    create_timeline()
    print("✅ Timeline diagram created")
    
    create_firewall_rules()
    print("✅ Firewall rules diagram created")
    
    print("\n🎉 All diagrams generated!")
    print("📂 Output directory: output/")
    print("💡 Professional appearance using AWS icons for semantic accuracy!")
    print("\nGenerated files:")
    print("- ldap_monitoring_architecture.png")
    print("- ldap_monitoring_coverage.png")
    print("- validation_matrix.png")
    print("- monitoring_timeline.png")
    print("- firewall_rules.png") 