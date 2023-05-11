require("dotenv").config();
const express = require("express");
const cors = require("cors");

const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

const app = express();
app.use(express.json());
app.use(cors());

app.get("/", (req, res) => {
    res.send(`** GET ${req.headers.host}/`);
});

//####################################################################################################################################################################################

app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    const user = await prisma.users.findUnique({
        where: {
            username,
        },
    });
    if (user) {
        if (bcrypt.compareSync(password, user.password)) {
            const token = jwt.sign(
                { id: user.id, username: user.username, role: user.role },
                process.env.SECRET
            );
            return res
                .status(200)
                .json({ status: 200, msg: "Login success", token });
        }
        return res.status(400).json({ msg: "username or password incorrect!" });
    }
    return res.status(400).json({ msg: "Login fail!" });
});

//####################################################################################################################################################################################

app.post("/register", async (req, res) => {
    const { username, password,role } = req.body;
    const user = await prisma.users.findUnique({
        where: {
            username,
        },
    });
    if (user) return res.json({ status: 400, msg: "username already exist!" });
    const encode = bcrypt.hashSync(password, bcrypt.genSaltSync(10));
    await prisma.users.create({
        data: {
            username,
            password: encode,
            role
        },
    });
    return res.json({ status: 200, msg: "Register success" });
});

//####################################################################################################################################################################################

app.post("/password", async (req, res) => {
    const { username, nPass } = req.body;
    if (!username) return res.status(400);
    const encode = bcrypt.hashSync(nPass, bcrypt.genSaltSync(10));
    await prisma.users.update({
        where: {
            username,
        },
        data: {
            password: encode,
        },
    });
    return res.json({ status: 200, msg: "Change password success" });
});

//####################################################################################################################################################################################

app.post("/auth", async (req, res) => {
    const { token } = req.body;
    if (!token) return res.status(400);
    const decode = jwt.verify(token, process.env.SECRET);
    return res.json({ status: 200, data: decode });
});

//####################################################################################################################################################################################

app.post("/getorder", async (req, res) => {
    const { token } = req.body;
    if (!token) return res.status(400);
    const decode = jwt.verify(token, process.env.SECRET);
    const order = await prisma.order.findMany({
        where: {
            address: {
                usersId: decode.id,
            },
        },
        include: {
            address: true,
        },
    });
    return res.status(200).json({ status: 200, data: order });
});

app.get("/todoorder", async (req, res) => {
    const order = await prisma.order.findMany({
        include: {
            address: true,
        },
    });
    return res.status(200).json({ status: 200, order });
});

app.post("/updateorder", async (req, res) => {
    const { id, status } = req.body;
    const order = await prisma.order.update({
        where: {
            id,
        },
        data: {
            status: !status,
        },
    });
    return res.status(200).json({ status: 200, order });
});

app.post("/order", async (req, res) => {
    const data = req.body;
    if (!data.token) return res.status(400);
    const username = jwt.verify(data.token, process.env.SECRET);
    const result = await prisma.$transaction(async (tx) => {
        const newAddress = await tx.address.create({
            data: {
                name: data.address.name,
                address: `${data.address.address} ${data.address.address2}`,
                pincode: data.address.pin,
                phone: data.address.phone,
                payment: data.address.payment,
                users: {
                    connect: {
                        username: username.username,
                    },
                },
            },
        });

        await tx.order.create({
            data: {
                name: data.order.name,
                size: data.order.size,
                amount: data.order.amount,
                price: data.order.price,
                status: data.order.status,
                address: {
                    connect: {
                        id: newAddress.id,
                    },
                },
            },
        });
        return newAddress;
    });
    return res.status(200).json(result);
});

//####################################################################################################################################################################################

app.listen(process.env.PORT, () => {
    console.log("Server running");
});
