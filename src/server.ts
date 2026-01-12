import { connectToDB } from "./config/db";
import dotenv from 'dotenv';
import http from 'http';
import app from "./app";


dotenv.config();

async function startServer(){
    await connectToDB();

    const server = http.createServer(app);
    server.listen(process.env.PORT, ()=>{
        console.log(`server is running to port ${process.env.PORT}`);
    })
}

startServer().catch(err=>{
    console.error('Error while starting the server');
    process.exit(1);
})