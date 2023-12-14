control 'AMZL-02-740100' do
  title 'The Amazon Linux 2 operating system must be configured to prohibit or restrict the use of
    functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management Component
    Local Service Assessment (PPSM CLSA) and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or
    unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict
    unused or unnecessary physical and logical ports/protocols on information systems.
    Operating systems are capable of providing a wide variety of functions and services. Some of the functions and
    services provided by default may not be necessary to support essential organizational operations. Additionally, it
    is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so
    increases risk over limiting the services provided by any one component.
    To support the requirements and principles of least functionality, the operating system must support the
    organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or
    services to only those required, authorized, and approved to conduct official business or to address authorized
    quality of life issues.'
  desc 'check', 'Inspect the firewall configuration and running services to verify that it is configured to prohibit
    or restrict the use of functions, ports, protocols, and/or services that are unnecessary or prohibited.
    Check which services are currently active with the following command:
    # firewall-cmd --list-all
    public (default, active)
    interfaces: enp0s3
    sources:
    services: dhcpv6-client dns http https ldaps rpc-bind ssh
    ports:
    masquerade: no
    forward-ports:
    icmp-blocks:
    rich rules:
    Ask the System Administrator for the site or program PPSM CLSA. Verify the services allowed by the firewall match
    the PPSM CLSA.
    If there are additional ports, protocols, or services that are not in the PPSM CLSA, or there are ports, protocols,
    or services that are prohibited by the PPSM Category Assurance List (CAL), this is a finding.'
  desc 'fix', "Update the host's firewall settings and/or running services to comply with the PPSM CLSA for the site
    or program and the PPSM CAL."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag satisfies: ['SRG-OS-000096-GPOS-00050', 'SRG-OS-000297-GPOS-00115']
  tag stig_id: 'AMZL-02-740100'
  tag cci: ['CCI-000382', 'CCI-002314']
  tag nist: ['CM-7 b', 'AC-17 (1)']
  tag subsystems: ['firewall', 'manual']
  tag 'host'
  tag 'container'

  if input('firewall_application_package')
    describe 'Manual review of third-party firewall needed' do
      skip "A manual review of firewall application is needed to determine if it is properly configured"
    end
  else

    firewalld_services_deny = input('firewalld_services_deny')
    firewalld_hosts_deny = input('firewalld_hosts_deny')
    firewalld_ports_deny = input('firewalld_ports_deny')
    firewalld_zones = input('firewalld_zones')
    iptables_rules = input('iptables_rules')

    if service('firewalld').running?

      # Check that the rules specified in 'firewalld_host_deny' are not enabled
      describe firewalld do
        firewalld_hosts_deny.each do |rule|
          it { should_not have_rule_enabled(rule) }
        end
      end

      # Check to make sure zones are specified
      if firewalld_zones.empty?
        describe "Firewalld zones are not specified. Check 'firewalld_zones' input." do
          subject { firewalld_zones.empty? }
          it { should be false }
        end
      end

      # Check that the services specified in 'firewalld_services_deny' and
      # ports specified in 'firewalld_ports_deny' are not enabled
      firewalld_zones.each do |zone|
        if firewalld.has_zone?(zone)
          zone_services = firewalld_services_deny[zone.to_sym]
          zone_ports = firewalld_ports_deny[zone.to_sym]

          if !zone_services.nil?
            describe firewalld do
              zone_services.each do |serv|
                it { should_not have_service_enabled_in_zone(serv, zone) }
              end
            end
          else
            describe "Services for zone '#{zone}' are not specified. Check 'firewalld_services_deny' input." do
              subject { zone_services.nil? }
              it { should be false }
            end
          end

          if !zone_ports.nil?
            describe firewalld do
              zone_ports.each do |port|
                it { should_not have_port_enabled_in_zone(port, zone) }
              end
            end
          else
            describe "Ports for zone '#{zone}' are not specified. Check 'firewalld_ports_deny' input." do
              subject { zone_ports.nil? }
              it { should be false }
            end
          end
        else
          describe "Firewalld zone '#{zone}' exists" do
            subject { firewalld.has_zone?(zone) }
            it { should be true }
          end
        end
      end
    elsif service('iptables').running?
      describe iptables do
        iptables_rules.each do |rule|
          it { should have_rule(rule) }
        end
      end
    else
      describe 'An application firewall is running' do
        subject { service('firewalld').running? || service('iptables').running? }
        it { should eq true }
      end
    end
  end
end
