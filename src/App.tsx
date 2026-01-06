import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import ErrorBoundary from "./components/ErrorBoundary";
import AmbientAura from "./components/Ghost/AmbientAura";
import Index from "./pages/Index";
import Session from "./pages/Session";
import Security from "./pages/Security";
import About from "./pages/About";
import Terms from "./pages/Terms";
import Contact from "./pages/Contact";
import Limitations from "./pages/Limitations";
import Contribute from "./pages/Contribute";
import Onion from "./pages/Onion";
import Tor from "./pages/Tor";
import Quarantine from "./pages/Quarantine";
import NotFound from "./pages/NotFound";
import InstallPrompt from "./components/Ghost/InstallPrompt";
import DecoyRoutes from "./components/Ghost/DecoyRoutes";
import SecurityStatusBar from "./components/Ghost/SecurityStatusBar";

const queryClient = new QueryClient();

const App = () => (
  <ErrorBoundary>
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <div className="relative min-h-screen">
          <AmbientAura />
          <div className="relative z-10">
            <SecurityStatusBar />
            <Toaster />
            <Sonner position="top-center" />
            <BrowserRouter>
              <Routes>
                <Route path="/" element={<Index />} />
                <Route path="/session" element={<Session />} />
                <Route path="/security" element={<Security />} />
                <Route path="/about" element={<About />} />
                <Route path="/terms" element={<Terms />} />
                <Route path="/contact" element={<Contact />} />
                <Route path="/limitations" element={<Limitations />} />
                <Route path="/contribute" element={<Contribute />} />
                <Route path="/tor" element={<Tor />} />
                <Route path="/onion" element={<Onion />} />
                {/* Quarantine page - escalation level 3 */}
                <Route path="/decoy" element={<Quarantine />} />
                {/* Decoy routes - weekly rotating endpoints */}
                <Route path="/ghost_debug/*" element={<DecoyRoutes type="debug" />} />
                <Route path="/api/docs" element={<DecoyRoutes type="api" />} />
                <Route path="/backup/*" element={<DecoyRoutes type="backup" />} />
                <Route path="/admin" element={<DecoyRoutes type="admin" />} />
                <Route path="/admin/*" element={<DecoyRoutes type="admin" />} />
                <Route path="/.env" element={<DecoyRoutes type="env" />} />
                <Route path="/config/*" element={<DecoyRoutes type="config" />} />
                <Route path="*" element={<NotFound />} />
              </Routes>
              <InstallPrompt showAfterMs={10000} position="bottom" />
            </BrowserRouter>
          </div>
        </div>
      </TooltipProvider>
    </QueryClientProvider>
  </ErrorBoundary>
);

export default App;
