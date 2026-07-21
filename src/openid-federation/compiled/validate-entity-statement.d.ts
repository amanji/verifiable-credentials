interface ValidatorFn {
    (data: unknown): boolean;
    errors?: Array<{ instancePath: string; message?: string }> | null;
}

declare const validate: ValidatorFn;
export default validate;
