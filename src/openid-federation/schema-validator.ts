import validateEntityStatement from './compiled/validate-entity-statement.js';
import validateEndpointError from './compiled/validate-endpoint-error.js';

interface ValidatorFn {
  (data: unknown): boolean;
  errors?: Array<{ instancePath: string; message?: string }> | null;
}

function validationErrors(validator: ValidatorFn): string {
  return (
    validator.errors?.map((err) => `${err.instancePath} ${err.message}`).join(', ') ??
    'Unknown validation error'
  );
}

export function validateEntityStatementSchema(payload: unknown): true {
  const valid = validateEntityStatement(payload);
  if (!valid) {
    throw new Error(
      `Entity statement schema validation failed: ${validationErrors(validateEntityStatement)}`
    );
  }
  return true;
}

export function validateEndpointErrorSchema(payload: unknown): true {
  const valid = validateEndpointError(payload);
  if (!valid) {
    throw new Error(
      `Endpoint error schema validation failed: ${validationErrors(validateEndpointError)}`
    );
  }
  return true;
}
