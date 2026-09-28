# StarX Store — OTT Subscription Selling Website

Full-stack website (zero external dependencies — sirf Node.js chahiye, v22.5+).

## Run kaise karein
1. Node.js install karein (v22.5 ya usse naya)
2. Folder mein: `node server.js`
3. Open: http://localhost:3000
4. Port change karna ho: `PORT=4000 node server.js`

## Admin Panel
- Pehli baar server start hone par admin account automatically banta hai:
  - Email: `admin@starx.store`
  - Password: `StarX@Admin2026` (ya `ADMIN_PASSWORD` env variable jo aapne set kiya)
- **Turant password change kar lein!** Admin panel mein `Settings` tab ka use karein, ya env var set karke DB file (`data/starx.db`) delete karke dobara seed karein.
- Admin panel: http://localhost:3000/admin

## Security (fake/temp sign-in kaise blocked hai)
- **Admin approval system**: Naya signup PENDING rehta hai — admin Approve karega tabhi login hoga
- **Disposable email blocklist**: tempmail, mailinator, yopmail waghera reject
- **Strong password rule**: 8+ chars, letter + number
- **Password hashing**: scrypt with random salt (plain text kabhi store nahi hota)
- **Session security**: HttpOnly + SameSite=Strict cookies, token DB mein hashed
- **Rate limiting**: signup 5/10min, login 8/10min per IP (brute-force protection)
- **Admin route protection**: non-admin users ko /admin se redirect

## Deployment (free hosting)
- **Render.com**: New Web Service → repo connect karein → Build: (none) → Start: `node server.js`
- **Railway**: `railway up` — done
- **VPS**: `node server.js` + nginx reverse proxy, ya `pm2 start server.js`

## Payment kaise collect hoga
Abhi manual UPI flow hai: admin Settings mein apni UPI ID daalein → user payment karke UTR ID submit karein → admin Paid + Deliver karega (credentials user ko dikhte hain).
Baad mein Razorpay/Cashfree jaisa gateway add kar sakte hain.

## Features
- Storefront with plan cards (admin se manage)
- User signup/login/dashboard (order history + delivered credentials)
- Admin panel: Dashboard stats, Orders (Paid/Deliver/Reject), Users (Approve/Block), Plans CRUD, Settings
