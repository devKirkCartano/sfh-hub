const express = require("express");
const app = express();

// app.use((req, res) => {
//     console.log("App received a request");
//     res.send({color:"red"})
// })


app.get("/m/:page", (req, res) =>{
    console.log(req.params);
    console.log("A get request")
    res.send("A get request");
})

app.post("/", (req, res) => {

    console.log("A get request" );
    res.send("A post request");

});

app.listen("3000", () => {
    console.log("Listening on port 3000");      
});