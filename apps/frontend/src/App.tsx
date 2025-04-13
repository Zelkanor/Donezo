import { BrowserRouter as Router,Routes,Route } from 'react-router-dom'
import Login from './pages/Auth/login'
import SignUp from './pages/Auth/signup'
import PrivateRoute from './routes/private_routes'
import Dashboard from './pages/Admin/dashboard'
import ManageTasks from './pages/Admin/manage_tasks'
import CreateTask from './pages/Admin/create_tasks'
import ManageUsers from './pages/Admin/manage_users'
import UserDashboard from './pages/User/user_dashboard'
import MyTasks from './pages/User/my_task'
import ViewTaskDetails from './pages/User/view_task_details'

function App() {


  return (
    <div>
      <Router>
        <Routes>
          <Route path="/login" element={<Login/>} />
          <Route path="/signup" element={<SignUp/>} />

          {/* Private Routes */}
          <Route element={<PrivateRoute allowedRoles={["admin"]}/>}>
            <Route path="/admin/dashboard" element={<Dashboard/>} />
            <Route path="/admin/tasks" element={<ManageTasks/>} />
            <Route path="/admin/create-task" element={<CreateTask/>} />
            <Route path="/admin/users" element={<ManageUsers/>} />
          </Route>


          {/* User Routes */}
          <Route element={<PrivateRoute allowedRoles={["admin"]}/>}>
            <Route path="/admin/dashboard" element={<UserDashboard/>} />
            <Route path="/user/tasks" element={<MyTasks/>} />
            <Route path="/user/task-details/:id" element={<ViewTaskDetails/>} />
          </Route>


        </Routes>
      </Router>
    </div>
  )
}

export default App
