# encoding: UTF-8

control 'C-1.1.3' do
  title 'Ensure auditing is configured for the Docker daemon'
  desc  "
    Audit all Docker daemon activities.

    As well as auditing the normal Linux file system and system calls, you should also audit the Docker daemon.  Because this daemon runs with `root` privileges. It is very important to audit its activities and usage.
  "
  desc  'rationale', "
    Audit all Docker daemon activities.

    As well as auditing the normal Linux file system and system calls, you should also audit the Docker daemon.  Because this daemon runs with `root` privileges. It is very important to audit its activities and usage.
  "
  desc  'check', "
    Verify that there are audit rules for the Docker daemon. For example, you could execute the following command:

    ```
    auditctl -l | grep /usr/bin/dockerd
    ```

    This should show the rules associated with the Docker daemon.
  "
  desc  'fix', "
    You should add rules for the Docker daemon.

    For example:

    Add the line below to the `/etc/audit/rules.d/audit.rules` file:
    ```
    -w /usr/bin/dockerd -k docker
    ```

    Then, restart the audit daemon using the following command

    ```
    systemctl restart auditd
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'IA-2 (2)', 'AU-2 a']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-IAM-APM', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-IAM-SUS', 'KSI-MLA-LET', 'KSI-MLA-OSM', 'KSI-MLA-RVL']
  tag nist_r4:               ['AC-2 f', 'AU-2 a', 'IA-2 (2)']
  tag cci:                   ['CCI-000011', 'CCI-000766', 'CCI-000123']
  tag cis_number:            '1.1.3'
  tag cis_rid:               '1.1.3'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-010103r1_rule'
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
    describe auditd do
    its('lines') { should include(match(/-w\s+\/usr\/bin\/dockerd/)) }
  end
  end
end
