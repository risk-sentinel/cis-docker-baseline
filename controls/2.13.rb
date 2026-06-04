# encoding: UTF-8

control 'C-2.13' do
  title 'Ensure that authorization for Docker client commands is enabled'
  desc  "
    You should use native Docker authorization plugins or a third party authorization mechanism with the Docker daemon to manage access to Docker client commands.

    Docker's out-of-the-box authorization model is currently \"all or nothing\".  This means that any user with permission to access the Docker daemon can run any Docker client command. The same is true for remote users accessing Docker's API to contact the daemon. If you require greater access control, you can create authorization plugins and add them to your Docker daemon configuration. Using an authorization plugin, a Docker administrator can configure granular access policies for managing access to the Docker daemon.

    Third party integrations of Docker may implement their own authorization models to require authorization with the Docker daemon outside of docker's native authorization plugin (i.e. Kubernetes, Cloud Foundry, Openshift).
  "
  desc  'rationale', "
    You should use native Docker authorization plugins or a third party authorization mechanism with the Docker daemon to manage access to Docker client commands.

    Docker's out-of-the-box authorization model is currently \"all or nothing\".  This means that any user with permission to access the Docker daemon can run any Docker client command. The same is true for remote users accessing Docker's API to contact the daemon. If you require greater access control, you can create authorization plugins and add them to your Docker daemon configuration. Using an authorization plugin, a Docker administrator can configure granular access policies for managing access to the Docker daemon.

    Third party integrations of Docker may implement their own authorization models to require authorization with the Docker daemon outside of docker's native authorization plugin (i.e. Kubernetes, Cloud Foundry, Openshift).
  "
  desc  'check', "
    To confirm this setting the dockerd start-up options and any settings in `/etc/docker/daemon.json` should be reviewed.

    To review the dockerd startup options, use:
    ```
    ps -ef | grep dockerd
    ```
    You should ensure that the `--authorization-plugin` parameter is set as appropriate if you are using docker native authorization.

    The contents of `/etc/docker/daemon.json` should also be reviewed.
  "
  desc  'fix', "
    Step 1: Install/Create an authorization plugin.

    Step 2: Configure the authorization policy as desired.

    Step 3: Start the docker daemon as below:
    ```
    dockerd --authorization-plugin= ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '2.13'
  tag cis_rid:               '2.13'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0213r1_rule'
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
      its(['authorization-plugins']) { should_not be_nil }
    end
  else
    describe 'CIS Docker daemon.json key authorization-plugins' do
      skip "host_daemon mode: /etc/docker/daemon.json not present — daemon is running with default flags. Operator confirms `dockerd --authorization-plugins` flag from process inventory."
    end
  end
  end
end
