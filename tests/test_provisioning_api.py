import time
import unittest

from iot_ca.provisioning_api import create_app


class FakeService:
    def __init__(self):
        self.status = 'authorized'

    def claim_device_enrollment(self, enrollment_id, token, payload):
        if enrollment_id != 'enrollment-1' or token != 'secret':
            raise PermissionError('Unknown enrollment or invalid token')
        self.status = 'pending'
        return {'status': self.status}

    def fulfill_device_enrollment(self, enrollment_id):
        if enrollment_id == 'enrollment-1':
            self.status = 'complete'

    def device_enrollment_status(self, enrollment_id, token):
        if enrollment_id != 'enrollment-1' or token != 'secret':
            raise PermissionError('Unknown enrollment or invalid token')
        return {
            'status': self.status,
            'error': None,
            'result': {'protocol': 'iotmd-enrollment-v1'}
            if self.status == 'complete' else None,
        }

    def create_automatic_device_enrollment(self, api_hostname):
        if api_hostname != 'device.local':
            raise ValueError('The Device API hostname must be one .local host name')
        return {
            'protocol': 'iotmd-enrollment-v1',
            'api_hostname': api_hostname,
            'portal_hostname': 'device.example.com',
        }

    def claim_device_renewal(self, enrollment_id, payload):
        if enrollment_id != 'enrollment-1':
            raise PermissionError('Unknown enrollment')
        self.renewal_id = payload['request_id']
        self.renewal_token = payload['poll_token']
        self.renewal_status = 'pending'
        return {'id': self.renewal_id, 'status': self.renewal_status}

    def fulfill_device_renewal(self, renewal_id):
        if renewal_id == self.renewal_id:
            self.renewal_status = 'complete'

    def device_renewal_status(self, renewal_id, token):
        if renewal_id != self.renewal_id or token != self.renewal_token:
            raise PermissionError('Unknown renewal or invalid token')
        return {
            'status': self.renewal_status, 'error': None,
            'result': {'protocol': 'iotmd-renewal-v1'}
            if self.renewal_status == 'complete' else None,
        }


class ProvisioningAPITests(unittest.TestCase):
    def setUp(self):
        self.service = FakeService()
        app = create_app(service=self.service)
        app.testing = True
        self.client = app.test_client()

    def test_enrollment_requires_bearer_token_and_exact_csr_set(self):
        url = '/v1/enrollments/enrollment-1'
        self.assertEqual(self.client.get(url).status_code, 401)
        headers = {'Authorization': 'Bearer secret'}
        incomplete = self.client.post(
            url, headers=headers, json={'portal_csr': 'only-one'}
        )
        self.assertEqual(incomplete.status_code, 400)
        accepted = self.client.post(url, headers=headers, json={
            'portal_csr': 'portal', 'api_csr': 'api',
            'renewal_csr': 'renewal',
        })
        self.assertEqual(accepted.status_code, 202)
        for _index in range(20):
            status = self.client.get(url, headers=headers)
            if status.json['status'] == 'complete':
                break
            time.sleep(0.01)
        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.json['status'], 'complete')
        self.assertEqual(
            status.json['result']['protocol'], 'iotmd-enrollment-v1'
        )
        self.assertEqual(status.headers['Cache-Control'], 'no-store')

    def test_private_lan_auto_enrollment_returns_host_bound_package(self):
        response = self.client.post(
            '/v1/auto-enrollments', json={'api_hostname': 'device.local'},
            environ_base={'REMOTE_ADDR': '192.168.1.50'},
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json['api_hostname'], 'device.local')
        public = self.client.post(
            '/v1/auto-enrollments', json={'api_hostname': 'device.local'},
            environ_base={'REMOTE_ADDR': '8.8.8.8'},
        )
        self.assertEqual(public.status_code, 403)

    def test_signed_renewal_is_scheduled_and_polled_with_its_token(self):
        payload = {
            'request_id': '1' * 32, 'poll_token': '2' * 64,
            'portal_csr': 'portal', 'api_csr': 'api',
            'renewal_csr': 'renewal', 'renewal_certificate': 'certificate',
            'proof_signature': 'signature',
        }
        accepted = self.client.post(
            '/v1/renewals/enrollment-1', json=payload
        )
        self.assertEqual(accepted.status_code, 202)
        self.assertEqual(accepted.json['poll'], '/v1/renewals/' + '1' * 32)
        headers = {'Authorization': 'Bearer ' + '2' * 64}
        for _index in range(20):
            status = self.client.get('/v1/renewals/' + '1' * 32, headers=headers)
            if status.json['status'] == 'complete':
                break
            time.sleep(0.01)
        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.json['result']['protocol'], 'iotmd-renewal-v1')


if __name__ == '__main__':
    unittest.main()
