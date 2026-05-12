/**
 * Negative fixture for SEC008-csrf-missing: Express app with csurf middleware.
 */

import express from "express";
import csurf from "csurf";

const app = express();
app.use(express.json());
app.use(csurf());

app.post("/withdraw", (req, res) => {
    const amount = req.body.amount;
    const account = req.body.account;
    res.json({ status: "ok", amount, account });
});

app.get("/balance", (req, res) => {
    res.json({ balance: 1000 });
});

app.listen(3000);
