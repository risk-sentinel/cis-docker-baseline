# encoding: UTF-8

control 'C-2.6' do
  title 'Ensure aufs storage driver is not used'
  desc  "
    Do not use `aufs` as the storage driver for your Docker instance.

    The `aufs` storage driver is the oldest storage driver used on Linux systems. It is based on a Linux kernel patch-set that is unlikely in future to be merged into the main OS kernel. The `aufs` driver is also known to cause some serious kernel crashes. `aufs` only has legacy support within systems using Docker. 

    Most importantly, `aufs` is not a supported driver in many Linux distributions using latest Linux kernels and has also been deprecated with Docker Engine release 20.10.
  "
  desc  'rationale', "
    Do not use `aufs` as the storage driver for your Docker instance.

    The `aufs` storage driver is the oldest storage driver used on Linux systems. It is based on a Linux kernel patch-set that is unlikely in future to be merged into the main OS kernel. The `aufs` driver is also known to cause some serious kernel crashes. `aufs` only has legacy support within systems using Docker. 

    Most importantly, `aufs` is not a supported driver in many Linux distributions using latest Linux kernels and has also been deprecated with Docker Engine release 20.10.
  "
  desc  'check', "
    Execute the below command and verify that `aufs` is not used as storage driver:
    ```
    docker info --format 'Storage Driver: {{ .Driver }}'
    ```
    The above command should not return `aufs`.
  "
  desc  'fix', "
    Do not explicitly use `aufs` as storage driver.

    For example, do not start Docker daemon as below:
    ```
    dockerd --storage-driver aufs
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '2.6'
  tag cis_rid:               '2.6'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0206r1_rule'
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
      its(['storage-driver']) { should_not eq 'aufs' }
    end
  else
    describe command('docker info --format 
end
{{.Driver}}
end
') do
      its('stdout.chomp') { should_not eq 'aufs' }
    end
  end
  end
end
