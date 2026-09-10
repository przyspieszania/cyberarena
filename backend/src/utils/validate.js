/**
 * Wraps a zod schema as an Express middleware. Validates req.body (or a
 * different part of the request) SERVER-SIDE — client-side validation is
 * never trusted. On failure, produces a normalized 400 through errorHandler.
 */
function validateBody(schema) {
  return (req, res, next) => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      const err = new Error('Nieprawidłowe dane wejściowe.');
      err.type = 'validation';
      err.details = result.error.flatten();
      return next(err);
    }
    req.validated = result.data;
    next();
  };
}

module.exports = { validateBody };
