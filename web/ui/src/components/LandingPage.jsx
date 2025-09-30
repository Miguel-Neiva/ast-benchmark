import { Link } from 'react-router-dom'
import './LandingPage.css'

function LandingPage() {
  return (
    <div className="landing-container">
      
        {/* Our new button. It's a link, but we'll style it as a button. */}
        <Link to="/dashboard" className="explore-button">
          Explore Application
        </Link>
    </div>
  )
}

export default LandingPage