# encoding: UTF-8

control 'C-7.3' do
  title 'Ensure that all Docker swarm overlay networks are encrypted'
  desc  "
    Ensure that all Docker swarm overlay networks are encrypted.

    By default, data exchanged between containers on nodes on the overlay network is not encrypted. This could potentially expose traffic between containers.
  "
  desc  'rationale', "
    Ensure that all Docker swarm overlay networks are encrypted.

    By default, data exchanged between containers on nodes on the overlay network is not encrypted. This could potentially expose traffic between containers.
  "
  desc  'check', "
    You should run the command below to ensure that each overlay network has been encrypted.
    ```
    docker network ls --filter driver=overlay --quiet | xargs docker network inspect --format '{{.Name}} {{ .Options }}'
    ```
  "
  desc  'fix', "
    You should create overlay networks the with `--opt encrypted` flag.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_number:            '7.3'
  tag cis_rid:               '7.3'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0703r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  if input('docker_target_mode') == 'container_only'
    tag implementation_status: 'not-applicable'
  else
    tag implementation_status: 'implemented'
  end
  tag exec_validated:          false

  if input('docker_target_mode') == 'container_only'
    describe "CIS Docker 7.3 — swarm overlay networks encrypted" do
      skip "not-applicable: AWS Fargate uses ECS scheduling; no Docker Swarm overlay networks exist."
    end
  else
    describe command('docker network ls --filter driver=overlay --format 
end
{{.Name}}
end
') do
    its('exit_status') { should eq 0 }
  end
  networks = command('docker network ls --filter driver=overlay --format 
end
{{.Name}}
end
').stdout.to_s.split.reject(&:empty?)
  offenders = networks.reject do |net|
    opts = command("docker network inspect #{net.shellescape} --format '{{json .Options}}'").stdout.to_s
    opts.include?('"encrypted":"true"')
  end
  describe 'Docker swarm overlay networks without encryption enabled' do
    subject { offenders }
    it { should be_empty }
  end
  end
end
