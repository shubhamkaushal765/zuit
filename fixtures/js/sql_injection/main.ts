/**
 * Positive fixture for SEC006-sql-injection: builds SQL via template literal.
 */

/** Fetch a user by ID using unsafe template literal interpolation. */
export function getUser(db: any, userId: string): Promise<any> {
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  return db.query(query);
}

/** Update a record using string concatenation. */
export function updateRecord(db: any, table: string, value: string): Promise<any> {
  const sql = "UPDATE " + table + " SET col = '" + value + "'";
  return db.query(sql);
}
