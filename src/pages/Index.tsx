import Navbar from '@/components/Ghost/Navbar';
import HeroSection from '@/components/Ghost/HeroSection';
import FeaturesSection from '@/components/Ghost/FeaturesSection';
import TransparencySection from '@/components/Ghost/TransparencySection';
import Footer from '@/components/Ghost/Footer';

const Index = () => {
  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <main>
        <HeroSection />
        <FeaturesSection />
        <TransparencySection />
      </main>
      <Footer />
    </div>
  );
};

export default Index;
