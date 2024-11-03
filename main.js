const express=require('express')
const jwt=require('jsonwebtoken')
const bcrypt=require('bcrypt')
const PORT=1805;
const cors = require('cors');
const app=express()
const jwtsecret='randomjwtsecret23'

app.use(cors({
    origin: 'http://127.0.0.1:5500', 
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'token']
}));
let users=[]
app.use(express.json());
app.post('/signup', async(req, res)=>{
const email=req.body.email;
const username=req.body.username;
const password=req.body.password;
//validating user
if(!email || !username || !password){
    return res.status(400).json({message:"All fields are required."})
}
const checkuser=users.find(user=>user.email===email || user.username===username)
if(checkuser){
    return res.status(400).json({message:'Username or email already exists.'})
}
const passlen=password.length;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecialChar = /[!@#$%^&*]/.test(password);
    if(passlen<8 || !hasLowerCase|| !hasUpperCase || !hasNumber || !hasSpecialChar){
        return res.status(400).json({
            message:'Password must be at least 8 characters long and include uppercase letters, lowercase letters, numbers, and special characters.' 
        })
    }
    //hash the password before storing into db
    const hashedPass= await bcrypt.hash(password, 10);
    const newUser={username, email, password:hashedPass};
    users.push(newUser)
     res.status(201).json({message:'User registeration successful.', redirect:'/'})
})
app.post('/login', async(req, res)=>{
    const {username, password}=req.body;
    if(!username || !password){
        return  res.status(400).json({
            message:"All fields are required"
        })
    }
        const checkuser=users.find(user=>user.username===username)
        if(!checkuser){
            return res.status(400).json({message:'User not= found.'})
        }
        const passMatch=await bcrypt.compare(password, checkuser.password)
        if(!passMatch){
            return res.status(401).json({message:"Password invalid"});
        }
        const token=jwt.sign({username:checkuser.username}, jwtsecret, {expiresIn:'1h'})
          res.status(200).json({ message: 'Login successful!', token:token, redirect: '/'})
          
})
const auth=(req, res, next)=>{
    const token=req.headers['token'];
    if(!token) return res.sendStatus(401);
    jwt.verify(token , jwtsecret, (err, user)=>{
        if(err) return res.sendStatus(403);
        req.user=user; next();
    });
    
}
app.get('/', auth, function(req, res){
res.send({message:'Welcome to home page'})
})
app.get('/logout', auth, (req, res) => {
    res.json({ message: "Logout ho gya", redirect: "/login" });
});

app.listen(PORT,()=>{
    console.log(`Server running fine at port:${PORT}`)
}) 