import type { Metadata } from 'next';
import Link from 'next/link';
import Navbar from '@/components/layout/Navbar';
import Footer from '@/components/layout/Footer';
import StickyFooterLayout from '@/components/layout/StickyFooterLayout';
import { Hero } from '@/components/hero';
import ServicesGrid from '@/components/sections/ServicesGrid';
import AIAutomationHero from '@/components/sections/ai-automation-hero';
import WhyChooseUs from '@/components/sections/WhyChooseUs';
import GlobalPresence from '@/components/sections/GlobalPresence';
import GlobalLocations from '@/components/sections/GlobalLocations';
import HowWeWork from '@/components/sections/HowWeWork';
import Testimonials from '@/components/sections/Testimonials';
import FAQSection from '@/components/sections/FAQSection';
import ClientsSection from '@/components/sections/ClientsSection';
import LatestBlogsSection from '@/components/sections/LatestBlogsSection';
import { homepageFaqs } from '@/data/homepage-faq';

const homepageFaqSchema = {
	'@context': 'https://schema.org',
	'@type': 'FAQPage',
	mainEntity: homepageFaqs.map(({ question, answer }) => ({
		'@type': 'Question',
		name: question,
		acceptedAnswer: {
			'@type': 'Answer',
			text: answer,
		},
	})),
};

export const metadata: Metadata = {
	title: { absolute: 'aibizmod | AI Automation, Software & Digital Services' },
	description:
		'aibizmod delivers AI automation, custom software development, web development, mobile apps, cloud hosting, IT consulting, and digital marketing for businesses worldwide.',
	alternates: { canonical: 'https://aibizmod.com' },
	openGraph: {
		title: 'aibizmod | AI Automation, Software & Digital Services',
		description:
			'aibizmod delivers AI automation, custom software development, web development, mobile apps, cloud hosting, IT consulting, and digital marketing for businesses worldwide.',
		url: '/',
	},
};

export default function Home() {
	return (
		<>
			<Navbar />
			<StickyFooterLayout footer={<Footer />}>
				<main>
				<script
					type="application/ld+json"
					dangerouslySetInnerHTML={{
						__html: JSON.stringify(homepageFaqSchema).replace(/</g, '\\u003c'),
					}}
				/>
				<Hero />
				<ServicesGrid />
					<AIAutomationHero />
					<WhyChooseUs />
<GlobalPresence />
				<GlobalLocations />
				<HowWeWork />
					<LatestBlogsSection />
					<section className="border-t border-cyan-100 bg-white px-6 py-20">
						<div className="mx-auto grid max-w-6xl gap-10 md:grid-cols-[1fr_auto] md:items-center">
							<div className="max-w-3xl">
								<p className="text-sm font-semibold uppercase tracking-[0.16em] text-cyan-700">
									Selected client case study
								</p>
								<h2 className="mt-4 text-3xl font-semibold leading-tight text-slate-900">
									Reducing LLM fine-tuning costs for SpaceLean
								</h2>
								<p className="mt-4 leading-relaxed text-slate-600">
									SpaceLean faced rising API costs and resource bottlenecks while running custom LLM workloads. aibizmod designed a lightweight fine-tuning workflow using Docker, Hugging Face, and customized caching.
								</p>
								<p className="mt-4 leading-relaxed text-slate-700">
									Reported client results: 70% API cost savings and 3x inference response speed.
								</p>
							</div>
							<Link
								href="/clients"
								className="inline-flex items-center justify-center rounded-full border border-cyan-200 px-6 py-3 text-sm font-semibold text-cyan-800 transition hover:border-cyan-400 hover:bg-cyan-50"
							>
								View client case studies
							</Link>
						</div>
					</section>
					<Testimonials />
					<FAQSection />
					<ClientsSection />
				</main>
			</StickyFooterLayout>
		</>
	);
}
