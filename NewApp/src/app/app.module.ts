import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { RouteReuseStrategy } from '@angular/router';

import { IonicModule, IonicRouteStrategy } from '@ionic/angular';

import { AppComponent } from './app.component';
import { AppRoutingModule } from './app-routing.module';

import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';
import { HttpClientModule } from '@angular/common/http';
import { HeaderComponent } from './components/header/header.component';
import { ProfileMenuComponent } from './components/profile-menu/profile-menu.component';
import { TabsComponent } from './components/tabs/tabs.component';
import { AuthService } from './services/auth.service'; // Importer AuthService







@NgModule({
  declarations: [AppComponent, ],
  imports: [BrowserModule, IonicModule.forRoot(), AppRoutingModule, HttpClientModule, IonicModule, HeaderComponent, TabsComponent, ProfileMenuComponent ],
  providers: [{ provide: RouteReuseStrategy, useClass: IonicRouteStrategy }, provideHttpClient(withInterceptorsFromDi()), AuthService],
  bootstrap: [AppComponent],
  exports: [HeaderComponent, ProfileMenuComponent, TabsComponent], // Permet de l'utiliser dans d'autres pages
})
export class AppModule {}
