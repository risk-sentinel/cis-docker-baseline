# encoding: UTF-8

control 'C-5.28' do
  title 'Ensure that Docker commands always make use of the latest version of their image'
  desc  "
    You should always ensure that you are using the latest version of the images within your repository and not cached older versions.

    Multiple Docker commands such as `docker pull`, `docker run` etc. are known to have an issue where by default, they extract the local copy of the image, if present, even though there is an updated version of the image with the same tag in the upstream repository. This could lead to using older images containing known vulnerabilites.
  "
  desc  'rationale', "
    You should always ensure that you are using the latest version of the images within your repository and not cached older versions.

    Multiple Docker commands such as `docker pull`, `docker run` etc. are known to have an issue where by default, they extract the local copy of the image, if present, even though there is an updated version of the image with the same tag in the upstream repository. This could lead to using older images containing known vulnerabilites.
  "
  desc  'check', "
    You should carry out the following steps:

    Step 1: Open your image repository and list the image version history for the image you are inspecting.

    Step 2: Observe the status when the `docker pull` command is triggered.

    If the status is shown as `Image is up to date`, it means that you are getting the cached version of the image.

    Step 3: Match the version of the image you are running to the latest version reported in your repository and this will tell you whether you are running the cached version or the latest copy.
  "
  desc  'fix', "
    You should use proper version pinning mechanisms (the \"latest\" tag which is assigned by default is still vulnerable to caching attacks) to avoid extracting cached older versions. Version pinning mechanisms should be used for base images, packages, and entire images. You can customize version pinning rules according to your requirements.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['IA-5 (1) (e)']
  tag cci:                   ['CCI-000200']
  tag cis_number:            '5.28'
  tag cis_rid:               '5.28'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0528r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag exec_validated:        false

  describe 'Requires manual review and attestation' do
    skip "Requires manual review and attestation provided for this control (\"latest version of image\" is enforced at build/deploy time by the consumer's image-pinning policy; operators attest from their CI/CD image-tag manifest)"
  end
end
