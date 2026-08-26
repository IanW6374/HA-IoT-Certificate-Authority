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


if __name__ == '__main__':
    unittest.main()
