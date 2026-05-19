# encoding: UTF-8

control 'C-4.9' do
  title 'Ensure that COPY is used instead of ADD in Dockerfiles'
  desc  "
    You should use the `COPY` instruction instead of the `ADD` instruction in the Dockerfile.

    The `COPY` instruction simply copies files from the local host machine to the container file system. The `ADD` instruction could potentially retrieve files from remote URLs and perform operations such as unpacking them. The `ADD` instruction therefore introduces security risks.  For example, malicious files may be directly accessed from URLs without scanning, or there may be vulnerabilities associated with decompressing them.
  "
  desc  'rationale', "
    You should use the `COPY` instruction instead of the `ADD` instruction in the Dockerfile.

    The `COPY` instruction simply copies files from the local host machine to the container file system. The `ADD` instruction could potentially retrieve files from remote URLs and perform operations such as unpacking them. The `ADD` instruction therefore introduces security risks.  For example, malicious files may be directly accessed from URLs without scanning, or there may be vulnerabilities associated with decompressing them.
  "
  desc  'check', "
    Run the command below to get the list of images:
    ```
    docker images 
    ```

    Run the command below against each image in the list above and look for any `ADD` instructions:
    ```
    docker history ```

    Alternatively, if you have access to the Dockerfile for the image, you should verify that there are no `ADD` instructions.
  "
  desc  'fix', "
    You should use `COPY` rather than `ADD` instructions in Dockerfiles.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['IA-5 (1) (e)', 'CM-6 a']
  tag cci:                   ['CCI-000200', 'CCI-000363']
  tag cis_number:            '4.9'
  tag cis_rid:               '4.9'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0409r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag exec_validated:        false

  describe 'Requires manual review and attestation' do
    skip "Requires manual review and attestation provided for this control (COPY-vs-ADD is a Dockerfile-only concern not visible from a running container; operators attest from Dockerfile review)"
  end
end
