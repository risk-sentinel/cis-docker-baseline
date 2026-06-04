# encoding: UTF-8

control 'C-5.3' do
  title 'Ensure that, if applicable, SELinux security options are set'
  desc  "
    SELinux is an effective and easy-to-use Linux application security system. It is available by default on some distributions such as Red Hat and Fedora.

    SELinux provides a Mandatory Access Control (MAC) system that greatly augments the default Discretionary Access Control (DAC) model. You can therefore add an extra layer of safety to your containers by enabling SELinux on your Linux host.
  "
  desc  'rationale', "
    SELinux is an effective and easy-to-use Linux application security system. It is available by default on some distributions such as Red Hat and Fedora.

    SELinux provides a Mandatory Access Control (MAC) system that greatly augments the default Discretionary Access Control (DAC) model. You can therefore add an extra layer of safety to your containers by enabling SELinux on your Linux host.
  "
  desc  'check', "
    You should run the following command

    ```
    docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: SecurityOpt={{ .HostConfig.SecurityOpt }} MountLabel={{ .MountLabel }} ProcessLabel={{ .ProcessLabel }}'
    ```

    This command returns all the security options currently configured on the containers listed. Note that even if an empty `SecurityOpt` is returned, the `MountLabel` and `ProcessLabel` values will indicate if SELinux is in use.
  "
  desc  'fix', "
    If SELinux is applicable for your Linux OS, you should use it.

    1. Set the SELinux State.
    2. Set the SELinux Policy.
    3. Create or import a SELinux policy template for Docker containers.
    4. Start Docker in daemon mode with SELinux enabled. For example:

    ```
    docker daemon --selinux-enabled
    ```

    or by adding the following to the `daemon.json` configuration file: 

    ```
    {
      \"selinux-enabled\": true
    }
    ```

    5. Start your Docker container using the security options. For example, 

    ```
    docker run --interactive --tty --security-opt label=level:TopSecret centos /bin/bash
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['IA-5 (1) (e)', 'SI-16']
  tag cci:                   ['CCI-000200', 'CCI-002823']
  tag cis_number:            '5.3'
  tag cis_rid:               '5.3'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0503r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  uri = input('c_5_3_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-5.3') if uri.to_s.empty?
  if uri.to_s.empty?
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (SELinux is not used on Fargate (AppArmor is the default LSM); host_daemon SELinux-enabled consumers attest from their security-options config) [Lift: set boundary_docs_base / c_5_3_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: input('attestation_max_age_days', value: 365))
    describe "Boundary policy attestation (C-5.3) (#{uri})" do
      it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current") { expect(doc.current?).to eq(true) }
    end
  end
end
