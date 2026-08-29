# encoding: UTF-8

control 'C-1.2.2' do
  title 'Ensure that the version of Docker is up to date'
  desc  "
    Frequent releases for Docker are issued which address security vulnerabilities, resolve product bugs and bring in new functionality. You should keep a tab on these product updates and upgrade as frequently as possible in line with the general IT security policy of your organization.

    By staying up to date on Docker updates, vulnerabilities in the software can be mitigated. An experienced attacker may be able to exploit known vulnerabilities resulting in them being able to attain inappropriate access or to elevate their privileges. If you do not ensure that Docker is running at the most current release consistent with the requirements of of your application, you may introduce unwanted behaviour and it is therefore important to ensure that you monitor software versions and upgrade in a timely fashion.
  "
  desc  'rationale', "
    Frequent releases for Docker are issued which address security vulnerabilities, resolve product bugs and bring in new functionality. You should keep a tab on these product updates and upgrade as frequently as possible in line with the general IT security policy of your organization.

    By staying up to date on Docker updates, vulnerabilities in the software can be mitigated. An experienced attacker may be able to exploit known vulnerabilities resulting in them being able to attain inappropriate access or to elevate their privileges. If you do not ensure that Docker is running at the most current release consistent with the requirements of of your application, you may introduce unwanted behaviour and it is therefore important to ensure that you monitor software versions and upgrade in a timely fashion.
  "
  desc  'check', "
    You should execute the command below in order to verify that the Docker version is up to date in line with the requirements of the application you are running. It should be noted that it is not a security requirement to be at the most up to date version, provided the version you are using does not contain any critical or high security vulnerabilities.
    ```
    docker version
    ```
  "
  desc  'fix', "
    You should monitor versions of Docker releases and make sure your software is updated as required.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '1.2.2'
  tag cis_rid:               '1.2.2'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-010202r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  if input('docker_target_mode') == 'container_only'
    tag implementation_status:  'inherited'
    tag inherited_from:         'aws-shared-responsibility'
    tag attestation_references: ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  else
    tag implementation_status:  'alternative'
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
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (\"up to date\" is a moving target tracked by the consumer's patch-management process; operators attest from their fleet-version inventory)"
    end
  end
end
