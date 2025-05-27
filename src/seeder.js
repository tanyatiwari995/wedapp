import dotenv from "dotenv"
import connectDB from "./config/db.js"
import { Admin } from "./models/Admin.js"
import bcrypt from "bcryptjs"

dotenv.config()



async function main() {
    connectDB()


    const hashedPassword = await bcrypt.hash("12345678", 10);

    const data = {
        username: "admin",
        phone: "+919876543210",
        password: hashedPassword,
    }

    const adminExists = await Admin.findOne({
        $or: [{ username: data.username }, { phone: data.phone }],
    });

    if (adminExists) {
        throw new Error("User already exists");
    }

    const admin = await Admin.create(data);

    console.log("Admin a/c created");;

    process.exit(1)
    
}

main();