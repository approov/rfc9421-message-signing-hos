import abilityTest from './Ability.test';
import complianceValidationTest from './ComplianceValidation.test';
import httpFieldsRfc9421Test from './HttpFieldsRfc9421.test';

export default function testsuite() {
  httpFieldsRfc9421Test();
  complianceValidationTest();
}