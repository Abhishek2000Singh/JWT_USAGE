const express = require('express');
const app = express();
const jwt = require("jsonwebtoken");
const { token } = require('morgan');
const PORT = process.env.PORT || 5000;
app.use(express.json());


const users = [
    {
        id: 1,
        username: "John",
        // email:"john@gmail.com",
        password: "john0908",
        isAdmin: true,
    },
    {
        id: 2,
        username: "Jane",
        // email:"jane@gmail.com",
        password: "jane0908",
        isAdmin: false,
    },
];

let refreshTokens = []

app.post("/api/refresh", (req, res) => {
    //take the refresh token from the user
    const refreshToken = req.body.token;


    //send error if there is no token or the token is invalid
    if (!refreshToken) {
        return res.status(401).json("you are not authenticated !")
    }
    if (!refreshTokens.includes(refreshToken)) {
        return res.status(403).json("refresh token is invalid !")
    }
    jwt.verify(refreshToken, "myRefreshSecretKey", (err, user) => {
        if (err) {
            console.log(err);
            return res.status(403).json("Refresh token is no longer valid!");
        }
        refreshTokens = refreshTokens.filter((token) => token !== refreshToken)

        const newAccessToken = generateAccessToken(user)
        const newRefreshToken = generateRefreshToken(user)

        refreshTokens.push(newRefreshToken);

        res.status(200).json({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
        });
    });


    //if all ok, create new access token, refresh token and send to user
})

const generateAccessToken = (user) => {
    return jwt.sign({ id: user.id, isAdmin: user.isAdmin },
        "mySecretKey",
        { expiresIn: '10m' })
}
const generateRefreshToken = (user) => {
    return jwt.sign({ id: user.id, isAdmin: user.isAdmin },
        "myRefreshSecretKey"
    )
}


// Middleware

// Login route
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find((u) => {
        return u.username === username && u.password === password;
    });
    if (user) {
        //generate and access token

        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);
        refreshTokens.push(refreshToken)
        res.json({
            username: user.username,
            isAdmin: user.isAdmin,
            accessToken,
            refreshToken
        })
    } else {
        res.status(400).json({ message: "Invalid username or password" })
    }
});

//Verify Function
const verify = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(" ")[1];
        console.log("Token received:", token);  // Debugging line
        jwt.verify(token, "mySecretKey", (err, user) => {
            if (err) {
                return res.status(403).json({ message: "Token is invalid" });
            }
            req.user = user;
            next();
        })
    } else {
        return res.status(401).json({ message: "Unauthorized" });
    }
}

app.delete("/api/users/:userId", verify, (req, res) => {
    console.log(req.user.id);

    console.log("Deleting user with ID:", req.params.userId); // Log the user ID from the URL
    console.log("Logged-in user:", req.user); // Log the logged-in user
    if ((req.user.id === parseInt(req.params.userId)) || (req.user.isAdmin)) {
        res.status(200).json("User Has Been Deleted !");
    } else {
        res.status(403).json({ message: "You are not authorized to delete this user" })
    }
})


//Logout Method
app.post("/api/logout",verify, (req,res)=>{
    const refreshToken = req.body.refreshToken;
    refreshTokens = refreshTokens.filter(token=>token!==refreshToken)
    res.json({message: "Logged out successfully" })
})



app.listen(PORT, () => {
    console.log(`Server running on port http://localhost:${PORT}`);
});
