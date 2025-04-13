import { Outlet } from "react-router-dom";

//@ts-ignore
const PrivateRoute = ({allowedRoles})=>{
    return <Outlet/>
}

export default PrivateRoute;