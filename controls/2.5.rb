# encoding: UTF-8

control 'C-2.5' do
  title 'Ensure insecure registries are not used'
  desc  "
    Docker considers a private registry either secure or insecure. By default, registries are considered secure.

    A secure registry uses TLS. A copy of registry's CA certificate is placed on the Docker host at `/etc/docker/certs.d/ /` directory. An insecure registry is one which does not have a valid registry certificate, or one not using TLS. Insecure registries should not be used as they present a risk of traffic interception and modification. 

    Additionally, once a registry has been marked as insecure commands such as `docker pull`, `docker push`, and `docker search` will not result in an error message and users may indefinitely be working with this type of insecure registry without ever being notified of the risk of potential compromise.
  "
  desc  'rationale', "
    Docker considers a private registry either secure or insecure. By default, registries are considered secure.

    A secure registry uses TLS. A copy of registry's CA certificate is placed on the Docker host at `/etc/docker/certs.d/ /` directory. An insecure registry is one which does not have a valid registry certificate, or one not using TLS. Insecure registries should not be used as they present a risk of traffic interception and modification. 

    Additionally, once a registry has been marked as insecure commands such as `docker pull`, `docker push`, and `docker search` will not result in an error message and users may indefinitely be working with this type of insecure registry without ever being notified of the risk of potential compromise.
  "
  desc  'check', "
    You should execute the command below to find out if any insecure registries are in use:
    ```
    docker info --format 'Insecure Registries:'
    ```
  "
  desc  'fix', "
    You should ensure that no insecure registries are in use.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'AC-8 a']
  tag cci:                   ['CCI-000381', 'CCI-000051']
  tag cis_number:            '2.5'
  tag cis_rid:               '2.5'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0205r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  if input('docker_target_mode') == 'container_only'
    tag implementation_status:  'inherited'
    tag inherited_from:         'aws-shared-responsibility'
    tag attestation_references: ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  else
    tag implementation_status:  'implemented'
  end
  tag exec_validated:           false

  if input('docker_target_mode') == 'container_only'
    uri = input('inherited_evidence_uri', value: '')
    uri = attestation_uri(:leveraged, 'aws-soc2-type2', ext: 'json') if uri.to_s.empty?
    if uri.to_s.empty?
      describe 'AWS shared-responsibility evidence (no leveraged source configured)' do
        skip 'inherited-from-aws: set leveraged_evidence_base / inherited_evidence_uri to the pulled AWS evidence manifest (SOC 2 / FedRAMP / ISO), or `saf attest apply`.'
      end
    else
      doc = document_attestation(uri, max_age_days: input('leveraged_evidence_max_age_days', value: 365))
      describe "AWS shared-responsibility leveraged evidence (#{uri})" do
        it('reachable') { expect(doc.connection_error).to be_nil, "evidence unreachable: #{doc.connection_error}" }
        it('exists') { expect(doc.exists?).to eq(true) }
        it("current") { expect(doc.current?).to eq(true) }
      end
    end
  else
    daemon_json_path = '/etc/docker/daemon.json'
  if file(daemon_json_path).exist?
    describe json(daemon_json_path) do
      its(['insecure-registries']) { should be_empty }
    end
  else
    describe 'CIS Docker daemon.json key insecure-registries' do
      skip "host_daemon mode: /etc/docker/daemon.json not present — daemon is running with default flags. Operator confirms `dockerd --insecure-registries` flag from process inventory."
    end
  end
  end
end
