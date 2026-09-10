import httpFieldsRfc9421Test from './HttpFieldsRfc9421.test';
import complianceValidationTest from './ComplianceValidation.test';

export default function testsuite() {
  httpFieldsRfc9421Test();
  complianceValidationTest();
}